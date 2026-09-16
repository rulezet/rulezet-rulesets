rule win_njrat_x7 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "identifies njRat"

    strings:
        $str_keys_1 = "[TAP]" wide
        $str_keys_2 = "[ENTER]" wide

        $str_func_1 = "VKCodeToUnicode" ascii
        $str_func_2 = "MapVirtualKey" ascii
        $str_func_3 = "capGetDriverDescriptionA" ascii

        $str_var_1 = "LastAS" ascii
        $str_var_2 = "LastAV" ascii
        $str_var_3 = "TempoSleep" ascii
        $str_var_4 = "DownloadHostOrNotURL" ascii
        $str_var_5 = "CopyMyFileDir" ascii

    condition:
        uint16(0) == 0x5A4D and 
        all of them 
}