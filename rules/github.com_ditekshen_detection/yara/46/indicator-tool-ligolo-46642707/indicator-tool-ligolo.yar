rule INDICATOR_TOOL_Ligolo {
    meta:
        author = "ditekSHen"
        description = "Detects Ligolo tool for establishing SOCKS5 or TCP tunnels from a reverse connection"
    strings:
        $p1 = "/ligolo/main.go" ascii
        $p2 = "/armon/go-socks5" ascii
        $s1 = "main.StartLigolo" fullword ascii
        $s2 = "main.handleRelay" fullword ascii
        $s3 = "main.startSocksProxy" fullword ascii
        $s4 = "_main.tlsFingerprint" fullword ascii
        $s5 = "main.verifyTlsCertificate" fullword ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf) and ((all of ($p*) and 1 of ($s*)) or all of ($s*) or (1 of ($p*) and 4 of ($s*)))
}