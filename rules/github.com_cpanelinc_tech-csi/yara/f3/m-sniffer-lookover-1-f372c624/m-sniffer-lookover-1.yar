rule M_Sniffer_LOOKOVER_1 {
    meta:
        author = "Mandiant"
    strings:
        $str1 = "TKEY" 
        $str2 = "FILTER" 
        $str3 = "DEVICE" 
        $str4 = "SNFILENAME" 
        $str5 = "/var/lib/libsyslog.so" 
        $code = {8B 55 F8 48 8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 00 00 48 8B 45 E0 48 01 C8 8B 00 88 02 8B 45 F8 83 C0 01 89 C2 48 8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 00 00 48 8B 45 E0 48 01 C8 8B 00 C1 E8 08 88 02 8B 45 F8 83 C0 02 89 C2 48 8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 00 00 48 8B 45 E0 48 01 C8 8B 00 C1 E8 10 88 02 8B 45 F8 83 C0 03 89 C2 48 8B 45 E8 48 01 C2 8B 45 FC 48 8D 0C 85 00 00 00 00 48 8B 45 E0 48 01 C8 8B 00 C1 E8 18 88 02 83 45 FC 01 83 45 F8 04}
    condition:
        uint32(0) == 0x464c457f and filesize < 5MB and all of them
}