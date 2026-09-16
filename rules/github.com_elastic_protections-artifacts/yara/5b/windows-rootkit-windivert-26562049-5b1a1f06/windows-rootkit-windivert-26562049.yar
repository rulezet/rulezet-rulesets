rule Windows_Rootkit_WinDivert_26562049 {
    meta:
        author = "Elastic Security"
        id = "26562049-a3c2-4cda-ade2-4896eb43b4fd"
        fingerprint = "0ee985008fde059f31ef5ff17b7b61052236f91ba6f2f23e00e8a50bed925beb"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Subject: 成都密思听科技有限公司, Version: <= 2.0.0.0"
        threat_name = "Windows.Rootkit.WinDivert"
        reference_sample = "2f43f4251be4d72dd56c91bf6cce475d379eb9ba6c4dda2be3022ea633d5e807"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] E6 88 90 E9 83 BD E5 AF 86 E6 80 9D E5 90 AC E7 A7 91 E6 8A 80 E6 9C 89 E9 99 90 E5 85 AC E5 8F B8 }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 57 00 69 00 6E 00 44 00 69 00 76 00 65 00 72 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x02-\x02][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "WinDivert32.pdb"
        $str2 = "WinDivert 2.2 driver" wide
        $str3 = "The WinDivert 2.2 driver [URL: https://reqrypt.org/windivert.html] [Bitcoin: 1C5vZVSbizPeZ8ydTYhUfm4LA2cNwBfcYh]" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}