rule Windows_VulnDriver_IBM_496c3bda {
    meta:
        author = "Elastic Security"
        id = "496c3bda-b158-4747-84c3-f0464add6149"
        fingerprint = "bf57ebf0d4eec2c388911433c826d8f48b8a751cac4f6abfa3f8ff652a7ca30f"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: IBM"
        threat_name = "Windows.VulnDriver.IBM"
        reference_sample = "dba8db472e51edd59f0bbaf4e09df71613d4dd26fd05f14a9bc7e3fc217a78aa"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 42 4D }
        $str1 = "sysconp.pdb"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1
}