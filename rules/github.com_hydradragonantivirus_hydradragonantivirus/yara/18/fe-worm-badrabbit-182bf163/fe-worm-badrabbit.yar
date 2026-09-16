rule FE_Worm_BADRABBIT
    {
        meta:
            author = "muhammad.umair"
            md5 = "1d724f95c61f1055f0d02c2154bbccd3"
            reference = "https://www.fireeye.com/blog/threat-research/2017/10/backswing-pulling-a-badrabbit-out-of-a-hat.html"
            rev = 1
        strings:
            $api1 = "WNetAddConnection2W" fullword
            $api2 = "CredEnumerateW" fullword
            $api3 = "DuplicateTokenEx" fullword
            $api4 = "GetIpNetTable"
            $del_tasks = "schtasks /Delete /F /TN drogon" ascii fullword wide
            $dropped_driver = "cscc.dat" ascii fullword wide
            $exec_fmt_str = "%ws C:\\Windows\\%ws,#1 %ws" ascii fullword wide
            $iter_encrypt = { 8D 44 24 3C 50 FF 15 ?? ?? ?? ?? 8D 4C 24 3C 8D 51 02 66 8B 31 83 C1 02 66 3B F7 75 F5 2B CA D1 F9 8D 4C 4C 3C 3B C1 74 07 E8 ?? ?? ?? ?? }
            $share_fmt_str = "\\\\%ws\\admin$\\%ws" ascii fullword wide
        condition:
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 500KB and all of them
    }