rule FE_Trojan_BADRABBIT_MIMIKATZ
    {
        meta:
            author = "muhammad.umair"
            md5 = "37945c44a897aa42a66adcab68f560e0"
            reference = "https://www.fireeye.com/blog/threat-research/2017/10/backswing-pulling-a-badrabbit-out-of-a-hat.html"
            rev = 1
        strings:
            $api1 = "WriteProcessMemory" fullword
            $api2 = "SetSecurityDescriptorDacl" fullword
            $api_str1 = "BCryptDecrypt" ascii fullword wide
            $mimi_str = "CredentialKeys" ascii fullword wide
            $wait_pipe_seq = { FF 15 ?? ?? ?? ?? 85 C0 74 63 55 BD B8 0B 00 00 57 57 6A 03 8D 44 24 1C 50 57 68 00 00 00 C0 FF 74 24 38 4B FF 15 ?? ?? ?? ?? 8B F0 83 FE FF 75 3B }
        condition:
            (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and filesize < 500KB and all of them
    }