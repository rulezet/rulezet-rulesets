rule Multi_Ransomware_BlackCat_70171625 {
    meta:
        author = "Elastic Security"
        id = "70171625-c29b-47c1-b572-2e6dc846a907"
        fingerprint = "f3f70f92fe9c044f4565fca519cb04a3a54536985c2614077ef92c3193fff9c1"
        creation_date = "2023-01-05"
        last_modified = "2023-09-20"
        threat_name = "Multi.Ransomware.BlackCat"
        reference_sample = "0c6f444c6940a3688ffc6f8b9d5774c032e3551ebbccb64e4280ae7fc1fac479"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $str0 = "}RECOVER-${EXTENSION}-FILES.txt"
        $str1 = "?access-key=${ACCESS_KEY}"
        $str2 = "${NOTE_FILE_NAME}"
        $str3 = "enable_network_discovery"
        $str4 = "enable_set_wallpaper"
        $str5 = "enable_esxi_vm_kill"
        $str6 = "strict_include_paths"
        $str7 = "exclude_file_path_wildcard"
        $str8 = "${ACCESS_KEY}${EXTENSION}"
    condition:
        all of them
}