rule Windows_Hacktool_Generic_42e0be24 {
    meta:
        author = "Elastic Security"
        id = "42e0be24-b631-4d1a-97d5-a9cee97fbbb3"
        fingerprint = "59220437136460f030274537d69889928260d9fc7055d1aec14c1795b05a8234"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s_load = "[DEBUG]Loading VirtualAlloc, VirtualProtect and RtlCopyMemory procedures"
        $s_copy = "[DEBUG]Copying shellcode to memory with RtlCopyMemory"
        $s_protect = "[DEBUG]Calling VirtualProtect to change memory region to PAGE_EXECUTE_READ"
        $s_decode = "[!]there was an error decoding the string to a hex byte array: %s"
        $s_done = "[-]Shellcode memory region changed to PAGE_EXECUTE_READ"
    condition:
        4 of them
}