rule Multi_Hacktool_LinPEAS_ng_ad70184f {
    meta:
        author = "Elastic Security"
        id = "ad70184f-4f91-4eb4-9efc-6afd4058e432"
        fingerprint = "3ee469f99797ad0de08abd89fa6634a464b26894023a45abf8d7f8f0e758e7f3"
        creation_date = "2022-12-22"
        last_modified = "2026-05-22"
        description = "LinPEAS detection based on the Files info module"
        threat_name = "Multi.Hacktool.LinPEAS-ng"
        reference_sample = "593333df3a1e109c73e8823e3929d52a7fc79a3064eb62004f33f11daca10d0b"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "multi"
    strings:
        $files_0 = "You have write privileges over" base64
        $files_1 = "-perm -4000 -type f ! -path" base64
        $files_2 = "You own the SUID file:" base64
        $files_3 = "(Unknown SUID binary!)" base64
        $files_4 = "open|access|no such file" base64
        $files_5 = "Checking misconfigurations of" base64
        $files_6 = "$(command -v capsh)" base64
        $files_7 = "Current env capabilities:" base64
        $files_8 = "find $HOMESEARCH -user root 2>/dev/null" base64
        $files_9 = "find /var/mail/ /var/spool/mail/ /private/var/mail -type f -ls" base64
    condition:
        5 of them
}