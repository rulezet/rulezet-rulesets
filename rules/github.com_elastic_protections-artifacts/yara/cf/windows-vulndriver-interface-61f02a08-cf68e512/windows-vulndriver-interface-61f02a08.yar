rule Windows_VulnDriver_Interface_61f02a08 {
    meta:
        author = "Elastic Security"
        id = "61f02a08-5817-465f-ba93-b8440dddc4dc"
        fingerprint = "968a7a3576f097dbd33b83afe3ffad4c1ca84789f6baa97cb0738b3ecbdc6185"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: Interface Corporation, Version: <= 1.61.20.0"
        threat_name = "Windows.VulnDriver.Interface"
        reference_sample = "11832c345e9898c4f74d3bf8f126cf84b4b1a66ad36135e15d103dbf2ac17359"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 6E 74 65 72 66 61 63 65 20 43 6F 72 70 6F 72 61 74 69 6F 6E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 43 00 50 00 32 00 58 00 37 00 32 00 43 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x3c][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x3d-\x3d][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x13][\x00-\x00]|[\x3d-\x3d][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x14-\x14][\x00-\x00])/
        $str1 = "CP2X72C.pdb"
        $str2 = "GPC-2X72C" wide
        $str3 = "GPC-2X72C Kernel Device Driver(SYS) WindowsNT" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3
}