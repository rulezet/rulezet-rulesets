rule INDICATOR_EXE_Python_Byte_Compiled {
    meta:
        author = "ditekSHen"
        description = "Detects python-byte compiled executables"
    strings:
        $s1 = "b64decode" ascii
        $s2 = "decompress" ascii
    condition:
        uint32(0) == 0x0a0df303 and filesize < 5KB and all of them
}