rule Windows_VulnDriver_TGSoft_58a9d5b4 {
    meta:
        author = "Elastic Security"
        id = "58a9d5b4-dcf9-4d31-8472-37df866d9401"
        fingerprint = "d9143396034f3f4b918097c4e084e30324eb369f8ce9aae28afb45e9ce178742"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: TG Soft S.a.s. Di Tonello Gianfranco e C., Version: <= 1.80.0.0"
        threat_name = "Windows.VulnDriver.TGSoft"
        reference_sample = "ef6d3c00f9d0aa31a218094480299ef73fc85146adf62fd0c2f4f88972c5c850"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 54 47 20 53 6F 66 74 20 53 2E 61 2E 73 2E 20 44 69 20 54 6F 6E 65 6C 6C 6F 20 47 69 61 6E 66 72 61 6E 63 6F 20 65 20 43 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 76 00 69 00 72 00 61 00 67 00 74 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x4f][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x50-\x50][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "VIRAGT.pdb"
        $str2 = "\\Device\\Harddisk0\\DR0"
        $str3 = "\\DosDevices\\X:\\...)"
        $str4 = "\\DosDevices\\X:)"
        $str5 = "VirIT Agent System" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and $subject_name and $original_file_name and $version and $str1 and $str2 and $str3 and $str4 and $str5
}