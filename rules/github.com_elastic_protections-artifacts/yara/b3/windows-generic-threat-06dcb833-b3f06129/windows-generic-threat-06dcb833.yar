rule Windows_Generic_Threat_06dcb833 {
    meta:
        author = "Elastic Security"
        id = "06dcb833-4aae-4be6-8433-5571841b7792"
        fingerprint = "3ff0bbf8d326661add9588aee99a2b5aac34fe719de7897aa84620c882d83095"
        creation_date = "2024-10-11"
        last_modified = "2024-11-26"
        threat_name = "Windows.Generic.Threat"
        reference_sample = "f7fde85aefb7123ef805c85394907ef73e0983499b49f2290a83aa2b0a2e5e9d"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 55 8B EC 81 EC 04 36 00 00 B8 75 00 00 00 66 89 85 0C DA FF FF B9 73 00 00 00 66 89 8D 0E DA FF FF BA 65 00 00 00 66 89 95 10 DA FF FF B8 72 00 00 00 66 89 85 12 DA FF FF B9 33 00 00 00 66 89 }
    condition:
        all of them
}