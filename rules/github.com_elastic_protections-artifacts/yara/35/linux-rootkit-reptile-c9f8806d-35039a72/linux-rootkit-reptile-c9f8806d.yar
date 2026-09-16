rule Linux_Rootkit_Reptile_c9f8806d {
    meta:
        author = "Elastic Security"
        id = "c9f8806d-102a-41d6-82bb-a2a136f51e67"
        fingerprint = "765329c644a95224493dcef81186504013ee5c1cda0860e4f5b31eab9857623f"
        creation_date = "2024-11-13"
        last_modified = "2024-11-22"
        threat_name = "Linux.Rootkit.Reptile"
        reference_sample = "331494780c1869e8367c3e16a2b99aeadc604c73b87f09a01dda00ade686675b"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "linux"
    strings:
        $str1 = "parasite_loader"
        $str2 = "parasite_loader/encrypt"
        $str3 = "kmatryoshka.c"
        $str4 = "parasite_loader.mod.c"
        $str5 = "reptile.mod.c"
        $str6 = "parasite_blob"
        $str7 = "name=reptile"
        $loader1 = "loader.c"
        $loader2 = "custom_rol32"
        $loader3 = "do_encode"
        $blob = "_blob"
    condition:
        ((3 of ($str*)) or (all of ($loader*))) and $blob
}