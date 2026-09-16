rule INDICATOR_EXE_Packed_dotNetProtector {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with dotNetProtector"
    strings:
        $s1 = "dotNetProtector" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}