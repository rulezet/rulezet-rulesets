rule Windows_Hacktool_Generic_033965e7 {
    meta:
        author = "Elastic Security"
        id = "033965e7-8c71-4a95-bd6c-c68b730d6cd3"
        fingerprint = "8bff946c35f5d325245313614a1e7911ccba69777316d97487cdc2da0e349e07"
        creation_date = "2026-09-21"
        last_modified = "2026-09-28"
        threat_name = "Windows.Hacktool.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s_trampoline = "[DEBUG]Calling WriteProcessMemory to overwrite AddressofEntryPoint at 0x%x with trampoline: 0x%x..."
        $s_overwrite = "[-]Successfully overwrote the AddressofEntryPoint"
        $s_machine = "[-]Machine type UNKOWN: 0x%x"
        $s_resume = "[+]Process resumed and shellcode executed"
        $s_header = "[-]ReadProcessMemory completed reading %d bytes for IMAGE_OPTIONAL_HEADER"
    condition:
        4 of them
}