rule Windows_VulnDriver_IObit_7604b52b {
    meta:
        author = "Elastic Security"
        id = "7604b52b-a6bc-4271-bf1b-4c53f2d74bdd"
        fingerprint = "eacce24dc052d1b6f92619612ab0d78a16803925dac2724a380389e36d3dd08d"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Name: IObitUnlocker.sys, Version: <= 1.3.0.20"
        threat_name = "Windows.VulnDriver.IObit"
        reference_sample = "98e3f4d3a2174a9872e327cb8142ab04d926043f9baaf8b1d10805e570aece91"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 49 00 4F 00 62 00 69 00 74 00 55 00 6E 00 6C 00 6F 00 63 00 6B 00 65 00 72 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x02][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x13][\x00-\x00][\x00-\x00][\x00-\x00]|[\x03-\x03][\x00-\x00][\x01-\x01][\x00-\x00][\x14-\x14][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "IObitUnlocker.pdb"
        $str2 = "File unlock driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}