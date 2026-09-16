rule Multi_Trojan_Mythic_e0ea7ef9 {
    meta:
        author = "Elastic Security"
        id = "e0ea7ef9-452c-404c-95ba-4057ec40ef4b"
        fingerprint = "57afe989db139314a7505a2ccc01367cdd13132318dc19b57d4b79f65bfe982c"
        creation_date = "2024-05-23"
        last_modified = "2024-06-12"
        threat_name = "Multi.Trojan.Mythic"
        reference_sample = "e091d63c8e8b0a32a3d25cffdf02419fdbec714f31e4061bafd80b1971831c5f"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $profile1 = "src/profiles/mod.rs"
        $profile2 = "src/profiles/http.rs"
        $rs_ssh1 = "src/ssh/spawn.rs"
        $rs_ssh2 = "src/ssh/agent.rs"
        $rs_ssh3 = "src/ssh/cat.rs"
        $rs_ssh4 = "src/ssh/upload.rs"
        $rs_ssh5 = "src/ssh/exec.rs"
        $rs_ssh6 = "src/ssh/download.rs"
        $rs_ssh7 = "src/ssh/rm.rs"
        $rs_ssh8 = "src/ssh/ls.rs"
        $rs_misc1 = "src/utils/linux.rs"
        $rs_misc2 = "src/portscan.rs"
        $rs_misc3 = "src/payloadvars.rs"
        $rs_misc4 = "src/getprivs.rs"
    condition:
        all of ($profile*) and 8 of ($rs*)
}