rule Remcos_keylogger_strings
{
    meta:
        description = "Detects Remcos keylogger strings."
        
    strings:
        $k1 = "Offline Keylogger Started" ascii wide
        $k2 = "Online Keylogger Started" ascii wide
        $k3 = "Keylogger initialization failure" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and any of them
}