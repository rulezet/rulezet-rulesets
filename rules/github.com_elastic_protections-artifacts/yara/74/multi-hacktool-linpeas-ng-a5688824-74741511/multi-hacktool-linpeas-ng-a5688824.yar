rule Multi_Hacktool_LinPEAS_ng_a5688824 {
    meta:
        author = "Elastic Security"
        id = "a5688824-9b13-4497-bce7-80362d68a4d5"
        fingerprint = "ae86f4b5040f667b0801ef771a20ffe89543d26935e0ed00f4e8827a7ad2b95a"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Files info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "cc3e69418622499a21248c762373642eb2a2b1073767f22f0dd0f65d0def94a5"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $files_0 = "You have write privileges over"
        $files_1 = "-perm -4000 -type f ! -path"
        $files_2 = "You own the SUID file:"
        $files_3 = "(Unknown SUID binary!)"
        $files_4 = "open|access|no such file"
        $files_5 = "Checking misconfigurations of"
        $files_6 = "$(command -v capsh)"
        $files_7 = "Current env capabilities:"
        $files_8 = "find $HOMESEARCH -user root 2>/dev/null"
        $files_9 = "find /var/mail/ /var/spool/mail/ /private/var/mail -type f -ls"
    condition:
        5 of them
}