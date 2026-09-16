rule Windows_VulnDriver_Rootkit_5b1586ea {
    meta:
        author = "Elastic Security"
        id = "5b1586ea-be99-4f4d-9546-9bda43748fe1"
        fingerprint = "226f51f3a5280b428c5341802c9c35c884809e0a950c3ed65fa5b99ceb6a14ab"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Beijing JoinHope Image Technology Ltd., Version: <= 2022.10.11.926"
        threat_name = "Windows.VulnDriver.Rootkit"
        reference_sample = "24c900024d213549502301c366d18c318887630f04c96bf0a3d6ba74e0df164f"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 42 65 69 6A 69 6E 67 20 4A 6F 69 6E 48 6F 70 65 20 49 6D 61 67 65 20 54 65 63 68 6E 6F 6C 6F 67 79 20 4C 74 64 2E }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe5][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x09][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x0a-\x0a][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe6-\xe6][\x07-\x07]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x02]|[\x00-\x9d][\x03-\x03])[\x0b-\x0b][\x00-\x00]|[\x0a-\x0a][\x00-\x00][\xe6-\xe6][\x07-\x07][\x9e-\x9e][\x03-\x03][\x0b-\x0b][\x00-\x00])/
        $str1 = "FilDriverx64.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $version and $str1
}