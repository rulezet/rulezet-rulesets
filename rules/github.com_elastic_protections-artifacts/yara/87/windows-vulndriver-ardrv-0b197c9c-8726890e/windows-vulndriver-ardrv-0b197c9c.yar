rule Windows_VulnDriver_Ardrv_0b197c9c {
    meta:
        author = "Elastic Security"
        id = "0b197c9c-e31f-41df-a822-505a29e32c25"
        fingerprint = "1cd5f4be32f4215cc4bc52d4a78dd5b63d39f6cd33fd5b8d7149a2ebea87c2df"
        creation_date = "2026-07-26"
        last_modified = "2026-08-11"
        description = "Name: ardrv.sys, Version: <= 2022.2.11.151"
        threat_name = "Windows.VulnDriver.Ardrv"
        reference_sample = "7d58338f7e5b4b77459835a2e057a07f81f72991a0e282d079fd5e227f68b5de"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $original_file_name = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 72 00 64 00 72 00 76 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}([\x00-\xff][\x00-\xff]([\x00-\xff][\x00-\x00]|[\x00-\xff][\x01-\x06]|[\x00-\xe5][\x07-\x07])[\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x00-\x01][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\xff][\x00-\xff]|[\x02-\x02][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\xff][\x00-\xff][\x00-\x0a][\x00-\x00]|[\x02-\x02][\x00-\x00][\xe6-\xe6][\x07-\x07][\x00-\x96][\x00-\x00][\x0b-\x0b][\x00-\x00]|[\x02-\x02][\x00-\x00][\xe6-\xe6][\x07-\x07][\x97-\x97][\x00-\x00][\x0b-\x0b][\x00-\x00])/
        $str1 = "ardrv.pdb"
        $str2 = "AppRemover Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $original_file_name and $version and $str1 and $str2
}