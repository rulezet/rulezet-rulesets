rule INDICATOR_TOOL_CNC_Chisel {
    meta:
        author = "ditekSHen"
        description = "Detect binaries using Chisel"
    strings:
        $s1 = "chisel-v" ascii
        $s2 = "sendchisel-v" ascii
        $s3 = "<-chiselclosedcookiedomainefenceempty" ascii
        $ws1 = "Sec-WebSocket-Key" ascii
        $ws2 = "Sec-WebSocket-Protocol" ascii
        $ws3 = "Sec-Websocket-Version" ascii
        $ws4 = "Sec-Websocket-Extensions" ascii
    condition:
        uint16(0) == 0x5a4d and (1 of ($s*) and 3 of ($ws*))
}