rule INDICATOR_TOOL_Ngrok {
    meta:
        author = "ditekSHen"
        description = "Detects Ngrok"
    strings:
        $s1 = "dashboard.ngrok.com" ascii
        $s2 = "go.ngrok.com/cmd/ngrok/main.go" ascii
        $s3 = "ngrok agent" ascii
        $s4 = "*ngrok.clientInfo" ascii
        $s5 = "'%s'  socket: '%s'  port: %d/edges/https/{{ .EdgeID }}/routes/{{ .ID }}/webhook_" ascii
        $s6 = "/{{ .ID }}/tunnel_sessions/{{ .ID }}/restart" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f or uint16(0) == 0xfacf) and (3 of them)
}