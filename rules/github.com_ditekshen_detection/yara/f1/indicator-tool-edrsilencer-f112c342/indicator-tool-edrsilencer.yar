rule INDICATOR_TOOL_EDRSilencer {
    meta:
        author = "ditekshen"
        description = "Detects EDRSilencer"
    strings:
        $s1 = "block \"C:\\Windows\\System32\\curl.exe\"" ascii
        $s2 = "blockedr" fullword ascii
        $s3 = "edrProcess" fullword ascii
        $s4 = "BlockEdrProcessTraffic" fullword ascii
        $s5 = "isInEdrProcessList" fullword ascii
        $s6 = "EDRSilencer.c" fullword ascii
        $v1 = "elastic-agent.exe" fullword ascii nocase
        $v2 = "CybereasonAV.exe" fullword ascii nocase
        $v3 = "SentinelAgent.exe" fullword ascii nocase
        $v4 = "fortiedr.exe" fullword ascii nocase
        $v5 = "MsMpEng.exe" fullword ascii nocase
        $v6 = "CylanceSvc.exe" fullword ascii nocase
    condition: 
        uint16(0) == 0x5a4d and (4 of ($s*) or (3 of ($s*) and 1 of ($v*)))
}