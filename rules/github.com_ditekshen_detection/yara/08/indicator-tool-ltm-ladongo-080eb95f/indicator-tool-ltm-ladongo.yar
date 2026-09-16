rule INDICATOR_TOOL_LTM_LadonGo {
    meta:
        author = "ditekSHen"
        description = "Detect LadonGo tool that assists in lateral movement across a network"
    strings:
        $f1 = "main.VulDetection" fullword ascii
        $f2 = "main.BruteFor" fullword ascii
        $f3 = "main.RemoteExec" fullword ascii
        $f4 = "main.Exploit" fullword ascii
        $f5 = "main.Noping" fullword ascii
        $f6 = "main.LadonScan" fullword ascii
        $f7 = "main.LadonUrlScan" fullword ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xface) and 5 of ($f*)
}