rule Windows_Rootkit_Nvidia_a9502150 {
    meta:
        author = "Elastic Security"
        id = "a9502150-627b-490b-8241-1511b86382d3"
        fingerprint = "46457c4ebfa3aae6b0d7254f5b8bf122656dac5b80782aeff4cb312d3ae964a2"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Name: nvoclock.sys, Version: <= 5.5.8.0"
        threat_name = "Windows.Rootkit.Nvidia"
        reference_sample = "4091d04132fc22929e859eca3de79269fd609711a76ebbacc411d5ff0065a531"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 6E 00 76 00 6F 00 63 00 6C 00 6F 00 63 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x04][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x04][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x05-\x05][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\x07][\x00-\x00]|[\x05-\x05][\x00-\x00][\x05-\x05][\x00-\x00][\x00-\x00][\x00-\x00][\x08-\x08][\x00-\x00])/
        $str1 = "nvoclk64.pdb"
        $str2 = "NVidia System Utility Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}