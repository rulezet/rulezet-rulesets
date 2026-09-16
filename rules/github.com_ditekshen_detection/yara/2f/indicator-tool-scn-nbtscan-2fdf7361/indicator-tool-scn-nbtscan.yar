rule INDICATOR_TOOL_SCN_NBTScan {
    meta:
        author = "ditekSHen"
        description = "Detects NBTScan scanner for open NETBIOS nameservers on a local or remote TCP/IP network"
    strings:
        $s1 = "[%s] is an invalid target (bad IP/hostname)" fullword ascii
        $s2 = "ERROR: no parse for %s -- %s" fullword ascii
        $s3 = "add_target failed" fullword ascii
        $s4 = "   -p <n>    bind to UDP Port <n> (default=%d)" fullword ascii
        $s5 = "process_response.c" fullword ascii
        $s6 = "currTarget != 0" fullword ascii
        $s7 = "parse_target.c" fullword ascii
        $s8 = "dump_packet.c" fullword ascii
        $s9 = "parse_target_cb.c" fullword ascii
        $s10 = "DUMP OF PACKET" fullword ascii
        $s11 = "lookup_hostname.c" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 10 of ($s*)
}