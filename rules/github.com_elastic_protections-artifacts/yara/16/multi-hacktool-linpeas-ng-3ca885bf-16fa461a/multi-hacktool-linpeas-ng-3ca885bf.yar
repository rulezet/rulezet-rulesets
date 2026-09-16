rule Multi_Hacktool_LinPEAS_ng_3ca885bf {
    meta:
        author = "Elastic Security"
        id = "3ca885bf-c737-4df7-a818-9cdeb49560a4"
        fingerprint = "1817bb75c9ce29ef72a6cdd2fd1d2c568b59f5d180ae7197a00d30f8af070bd4"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the User info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $user_0 = "Current user Login and Logout hooks" base64
        $user_1 = "/var/db/SystemKey" base64
        $user_2 = "Do I have PGP keys?" base64
        $user_3 = "$(xclip -o -selection clipboard" base64
        $user_4 = "timeout 1 sudo -S -l" base64
        $user_5 = "You can create a file in /etc/sudoers.d/" base64
        $user_6 = "The escalation didn't work..." base64
        $user_7 = "$(command -v doas)" base64
        $user_8 = "UserShell RealName RecordName Password NFSHomeDirectory" base64
        $user_9 = "^PASS_MAX_DAYS\\|^PASS_MIN_DAYS\\|^PASS_WARN_AGE\\|^ENCRYPT_METHOD" base64
    condition:
        5 of them
}