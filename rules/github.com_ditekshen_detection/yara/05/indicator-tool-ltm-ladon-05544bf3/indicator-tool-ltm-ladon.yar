rule INDICATOR_TOOL_LTM_Ladon {
    meta:
        author = "ditekSHen"
        description = "Detect Ladon tool that assists in lateral movement across a network"
    strings:
        $d1 = "Ladon.VncSharp.dll" fullword ascii
        $d2 = "Ladon.Renci.SshNet.dll" fullword ascii
        $s1 = "Ladon." ascii
        $s2 = "nowPos" fullword ascii
        $s3 = "Scan" fullword ascii
        $s4 = "QLZ_STREAMING_BUFFER" fullword ascii
        $s5 = "sizeDecompressed" fullword ascii
        $s6 = "UpdateByte" fullword ascii
        $s7 = "kNumBitPriceShiftBits" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($d*) or all of ($s*) or (1 of ($d*) and 5 of ($s*)))
}