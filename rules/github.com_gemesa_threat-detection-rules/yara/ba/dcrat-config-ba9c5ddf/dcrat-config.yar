rule DCRat_config
{
    meta:
        description = "Detects DCRat configuration field names."
        reference = "Settings.cs"
        
    strings:
        $f1 = "Por_ts" ascii wide
        $f2 = "Hos_ts" ascii wide
        $f3 = "Key" ascii wide
        $f4 = "Paste_bin" ascii wide
        $f5 = "BS_OD" ascii wide
        $f6 = "Hw_id" ascii wide
        $f7 = "Anti_Process" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and 5 of them
}