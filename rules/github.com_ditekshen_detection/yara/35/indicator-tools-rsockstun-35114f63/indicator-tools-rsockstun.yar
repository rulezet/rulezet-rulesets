rule INDICATOR_TOOLS_rsockstun {
    meta:
        author = "ditekShen"
        description = "Detects rsockstun"
    strings:
        $s1 = "main.connectviaproxy" ascii
        $s2 = "main.connectForSocks" ascii
        $s3 = "main.listenForClients" ascii
        $s4 = "main.listenForSocks" ascii
        $s5 = "Proxy-Authorization: NTLM TlRMTVNTUAABAAAABoIIAAAAAAAAAAAAAAAAAAAAAAA=" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and all of them
}