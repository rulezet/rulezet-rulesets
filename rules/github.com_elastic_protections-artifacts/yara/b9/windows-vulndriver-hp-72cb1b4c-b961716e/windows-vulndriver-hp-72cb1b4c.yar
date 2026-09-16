rule Windows_VulnDriver_HP_72cb1b4c {
    meta:
        author = "Elastic Security"
        id = "72cb1b4c-31a5-46fb-a5b6-8e860965e4bc"
        fingerprint = "336980c158973dfa4dbe99bb5827135a4686fce3c7fc96f064a13a112154365a"
        creation_date = "2026-05-22"
        last_modified = "2026-07-13"
        description = "Subject: HP Inc., Version: <= 1.0.0.0"
        threat_name = "Windows.VulnDriver.HP"
        reference_sample = "a4680fabf606d6580893434e81c130ff7ec9467a15e6534692443465f264d3c9"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 48 50 20 49 6E 63 2E }
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 48 00 70 00 50 00 6F 00 72 00 74 00 49 00 6F 00 78 00 36 00 34 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff][\x00-\x00][\x00-\x00][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x00][\x00-\x00][\x01-\x01][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00][\x00-\x00])/
        $str1 = "HpPortIO.pdb"
        $str2 = "HpPortIo" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $original_file_name and $version and $str1 and $str2
}