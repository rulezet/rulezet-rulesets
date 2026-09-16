rule INDICATOR_TOOL_CNC_Earthworm {
    meta:
        author = "ditekSHen"
        description = "Detects Earthworm C&C Windows/macOS tool"
    strings:
        $s1 = "lcx_tran 0.0.0.0:%d <--[%4d usec]--> %s:%d" fullword ascii
        $s2 = "ssocksd 0.0.0.0:%d <--[%4d usec]--> socks server" fullword ascii
        $s3 = "rcsocks 0.0.0.0:%d <--[%4d usec]--> 0.0.0.0:%d" fullword ascii
        $s4 = "rssocks %s:%d <--[%4d usec]--> socks server" fullword ascii
        $s5 = "--> %3d <-- (close)used/unused  %d/%d" fullword ascii
        $s6 = "<-- %3d --> (open)used/unused  %d/%d" fullword ascii
        $s7 = "--> %d start server" ascii
        $s8 = "Error on connect %s:%d [proto_init_cmd_rcsocket]" fullword ascii
        $url = "http://rootkiter.com/EarthWrom/" nocase fullword ascii
    condition:
        (uint16(0) == 0xfacf or uint16(0) == 0x5a4d) and (5 of ($s*) or $url)
}