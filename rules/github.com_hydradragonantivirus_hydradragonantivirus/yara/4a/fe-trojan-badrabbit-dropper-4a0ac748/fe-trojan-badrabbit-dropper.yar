rule FE_Trojan_BADRABBIT_DROPPER
    {
        meta:
            author = "muhammad.umair"
            md5 = "fbbdc39af1139aebba4da004475e8839"
            reference = "https://www.fireeye.com/blog/threat-research/2017/10/backswing-pulling-a-badrabbit-out-of-a-hat.html"
            rev = 1
        strings:
            $api1 = "GetSystemDirectoryW" fullword
            $api2 = "GetModuleFileNameW" fullword
            $dropped_dll = "infpub.dat" ascii fullword wide
            $exec_fmt_str = "%ws C:\\Windows\\%ws,#1 %ws" ascii fullword wide
            $extract_seq = { 68 ?? ?? ?? ?? 8D 95 E4 F9 FF FF 52 FF 15 ?? ?? ?? ?? 85 C0 0F 84 C4 00 00 00 8D 85 A8 ED FF FF 50 8D 8D AC ED FF FF E8 ?? ?? ?? ?? 85 C0 0F 84 AA 00 00 00 }
        condition:
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 500KB and all of them
    }