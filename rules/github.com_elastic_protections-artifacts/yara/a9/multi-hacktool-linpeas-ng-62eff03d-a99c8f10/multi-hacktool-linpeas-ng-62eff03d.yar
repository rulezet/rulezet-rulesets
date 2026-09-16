rule Multi_Hacktool_LinPEAS_ng_62eff03d {
    meta:
        author = "Elastic Security"
        id = "62eff03d-146c-411d-9ee4-418ef94e4003"
        fingerprint = "784fa26c75dbb9deecfacf2098147554706b1c40ab84aa625bc8c8df84fc7cf5"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the User info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $user_0 = "Current user Login and Logout hooks"
        $user_1 = "/var/db/SystemKey"
        $user_2 = "Do I have PGP keys?"
        $user_3 = "$(xclip -o -selection clipboard"
        $user_4 = "timeout 1 sudo -S -l"
        $user_5 = "You can create a file in /etc/sudoers.d/"
        $user_6 = "The escalation didn't work..."
        $user_7 = "$(command -v doas)"
        $user_8 = "UserShell RealName RecordName Password NFSHomeDirectory"
        $user_9 = "^PASS_MAX_DAYS\\|^PASS_MIN_DAYS\\|^PASS_WARN_AGE\\|^ENCRYPT_METHOD"
    condition:
        5 of them
}