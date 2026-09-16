rule INDICATOR_TOOL_SCN_PortScan {
    meta:
        author = "ditekSHen"
        description = "Detects a port scanner tool observed as second or third stage post-compromise or dropped by malware."
    strings:
        $s1 = "HEAD / HTTP/1.0" fullword ascii
        $s2 = "Result.txt" fullword ascii
        $s3 = "Example: %s SYN " ascii
        $s4 = "Performing Time: %d/%d/%d %d:%d:%d -->" fullword ascii
        $s5 = "Bind On IP: %d.%d.%d.%d" fullword ascii
        $s6 = "SYN Scan: About To Scan %" ascii
        $s7 = "Normal Scan: About To Scan %" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}