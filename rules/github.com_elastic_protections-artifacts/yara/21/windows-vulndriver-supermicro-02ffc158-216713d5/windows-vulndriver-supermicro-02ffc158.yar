rule Windows_VulnDriver_Supermicro_02ffc158 {
    meta:
        author = "Elastic Security"
        id = "02ffc158-c409-4666-9a9c-5074b0826bd1"
        fingerprint = "9f3276de08136f4a90c86d70faee0195a159f221c2d9e95348c730d6d88c1b5b"
        creation_date = "2026-05-22"
        last_modified = "2026-07-29"
        description = "Subject: Super Micro Computer, Inc."
        threat_name = "Windows.VulnDriver.Supermicro"
        reference_sample = "d6518cb6dc0cfdfefb9e2210e3de18867748a77153fa11bc7263cdbc58919815"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 53 75 70 65 72 20 4D 69 63 72 6F 20 43 6F 6D 70 75 74 65 72 2C 20 49 6E 63 2E }
        $str1 = "WinIo.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}