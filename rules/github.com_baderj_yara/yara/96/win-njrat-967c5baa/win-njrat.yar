rule win_njrat {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "identifies njRat version 0.7d"

    strings:
        $str_1 = "[TAP]" wide
        $str_2 = "[ENTER]" wide
        $str_3 = "cmd.exe /C Y /N /D Y /T 1 & Del" wide
        $str_4 = "Download ERROR" wide
        $str_5 = "Executed As" wide
        $str_6 = "Updating To" wide

    condition:
        uint16(0) == 0x5A4D and 
        all of them 
}