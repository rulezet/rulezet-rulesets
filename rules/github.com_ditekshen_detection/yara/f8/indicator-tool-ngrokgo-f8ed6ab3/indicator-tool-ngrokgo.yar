rule INDICATOR_TOOL_NgrokGo {
    meta:
        author = "ditekSHen"
        description = "Detects Go implementation variant for Ngrok"
    strings:
        $s1 = "/codegangsta/inject" fullword wide
        $s2 = "go.ngrok.com/" ascii
        $s3 = "GetIsNgrokDomain" ascii
        $s4 = "GetNgrokMetering" ascii
        $s5 = "*cli.ngrokService" ascii
        $s6 = "GetAllowNgrokLink" ascii
        $s7 = "ngrok {{.Name}}{{if .Flags}}" ascii
        $s8 = "github.com/nikolay-ngrok/" ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}