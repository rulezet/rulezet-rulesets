rule sliver_binary_native {
    meta:
        author = "Kev Breen @kevthehermit"
        description = "Detects unmodified Sliver implant generated for Windows, Linux or MacOS"
    strings: 
        $sliverpb = "sliverpb"
        $bishop_git = "github.com/bishopfox/"
        $encryption = "chacha20poly1305"
    condition:
                (
            (uint16(0) == 0x5a4d) or 
            (uint32(0)==0x464c457f) or 
            (uint32(0) == 0xfeedfacf) or 
            (uint32(0) == 0xcffaedfe) or 
            (uint32(0) == 0xfeedface) or 
            (uint32(0) == 0xcefaedfe) 
        )
                and $sliverpb
        and $bishop_git
        and $encryption
}