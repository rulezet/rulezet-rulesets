rule Windows_Hacktool_Generic_922943d8 {
    meta:
        author = "Elastic Security"
        id = "922943d8-9008-4a3d-9b56-4892636140ec"
        fingerprint = "c606a76ae0b427bea0eec8e457593a7a694d795773f1af23481ccbfa54b6de82"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s_registry = "[+] Looking for the 'Registry Editor' window..." ascii fullword
        $s_listview = "[+] Looking for the 'SysListView32' window..." ascii fullword
        $s_terminate = "[+] RegEdit process termination successfull." ascii fullword
        $s_empty = "[-] List view is empty." ascii fullword
        $s_alloc = "[+] Allocating memory in the remote process..." ascii fullword
        $s_post = "[+] Posting message to the target window..." ascii fullword
    condition:
        4 of them
}