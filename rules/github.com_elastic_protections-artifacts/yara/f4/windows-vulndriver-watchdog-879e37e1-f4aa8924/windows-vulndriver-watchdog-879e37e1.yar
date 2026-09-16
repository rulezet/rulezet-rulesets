rule Windows_VulnDriver_WatchDog_879e37e1 {
    meta:
        author = "Elastic Security"
        id = "879e37e1-813f-4778-9dce-c5317f57e288"
        fingerprint = "8ff917baccb5fb6fbc0e6da9172609a9da38d558780f5fe9acf61da3d81066a7"
        creation_date = "2025-09-02"
        last_modified = "2026-07-29"
        threat_name = "Windows.VulnDriver.WatchDog"
        reference_sample = "5af1dae21425dda8311a2044209c308525135e1733eeff5dd20649946c6e054c"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $wamsdk = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 77 00 61 00 6D 00 73 00 64 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $amsdk = { 4F 00 72 00 69 00 67 00 69 00 6E 00 61 00 6C 00 46 00 69 00 6C 00 65 00 6E 00 61 00 6D 00 65 00 00 00 61 00 6D 00 73 00 64 00 6B 00 2E 00 73 00 79 00 73 00 00 00 }
        $version = /V\x00S\x00_\x00V\x00E\x00R\x00S\x00I\x00O\x00N\x00_\x00I\x00N\x00F\x00O\x00\x00\x00{0,4}\xbd\x04\xef\xfe[\x00-\xff]{4}(([\x00-\x01][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\x06][\x00-\x00])([\x00-\x64][\x00-\x00])|([\x00-\xff][\x00-\xff])([\x00-\x00][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x00][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\xff][\x00-\xff])|([\x00-\x01][\x00-\x00])([\x00-\x01][\x00-\x00])([\x00-\xff][\x00-\xff])([\x00-\x63][\x00-\x00]))/
        $str1 = "WatchDog Antimalware Driver" wide
    condition:
        int16(uint32(0x3C) + 0x5c) == 0x0001 and int16(uint32(0x3C) + 0x18) == 0x020b and ($wamsdk or $amsdk) and $version and $str1
}