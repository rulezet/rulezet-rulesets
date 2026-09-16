rule Remcos_c2_strings
{
    meta:
        description = "Detects Remcos C2 connection strings."
        
    strings:
        $s1 = "Connection Error: Unable to create socket" ascii wide
        $s2 = "Connected   | " ascii wide
        $s3 = "TLS On" ascii wide
        $s4 = "TLS Off" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and 2 of them
}