rule Windows_VulnDriver_IBM_7be3f2be {
    meta:
        author = "Elastic Security"
        id = "7be3f2be-73fe-4b14-b7f8-5f32216e81b2"
        fingerprint = "45e723c54343c10c29639cb6722194c430f0dfc3918370218bd89a96b9f881be"
        creation_date = "2026-05-22"
        last_modified = "2026-07-20"
        description = "Subject: IBM Polska Sp. z o.o."
        threat_name = "Windows.VulnDriver.IBM"
        reference_sample = "1c8dfa14888bb58848b4792fb1d8a921976a9463be8334cff45cc96f1276049a"
        severity = 50
        arch_context = "x86"
        scan_context = "file"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $subject_name = { 06 03 55 04 03 [2] 49 42 4D 20 50 6F 6C 73 6B 61 20 53 70 2E 20 7A 20 6F 2E 6F 2E }
        $str1 = "CITMDRV_IA64.pdb"
        $str2 = "IOCTL_MAP_MEM"
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and $subject_name and $str1 and $str2
}