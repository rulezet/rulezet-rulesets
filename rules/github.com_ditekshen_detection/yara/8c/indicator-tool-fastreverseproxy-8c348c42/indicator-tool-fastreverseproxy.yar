rule INDICATOR_TOOL_FastReverseProxy {
    meta:
        author = "ditekSHen"
        description = "Detects Fast Reverse Proxy (FRP) tool"
    strings:
        $x1 = "<title>frp client admin UI</title>" ascii
        $x2 = "https://github.com/fatedier/frp" ascii
        $s1 = ").SetLogin" ascii
        $s2 = ").SetPing" ascii
        $s3 = ").SetNewWorkConn" ascii
        $s4 = ").ServeHTTP" ascii
        $s5 = ").Middleware" ascii
        $s6 = "frpc proxy config error:" ascii
        $s7 = "frpc sudp visitor proxy is close" ascii
    condition:
        uint16(0) == 0x5a4d and (all of ($x*) or (1 of ($x*) and 4 of ($s*)) or (all of ($s*)))
}