rule INDICATOR_TOOL_PROX_lanproxy {
    meta:
        author = "ditekSHen"
        description = "Detects lanproxy-go-client"
    strings:
        $s1 = "serverShare" fullword ascii
        $s2 = "parkingOnChan" fullword ascii
        $s3 = "{{join .Names \", \"}}{{\"\\t\"}}{{.Usage}}{{end}}{{end}}{{end}}{{end}}{{" ascii
        $s4 = "</table></thead></tbody>" fullword ascii
        $s5 = "value=aacute;abreve;addressagrave;alt -> andand;angmsd;angsph;any -> apacir;approx;articleatilde;barvee;barwed;bdoUxXvbecaus;ber" ascii
        $s6 = "/dev/urandom127.0.0.1:" ascii
        $s7 = "non-IPv4 addressnon-IPv6 addressntrianglelefteq;object is remotepacer: H_m_prev=reflect mismatchregexp: Compile(remote I/O error" ascii
        $s8 = ".WithDeadline(.in-addr.arpa." ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and 6 of them
}