rule DCRat_VM_detection
{
    meta:
        description = "Detects DCRat VM detection via WMI."
        reference = "Anti_Analysis.cs"
        
    strings:
        $wmi1 = "Win32_CacheMemory" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and all of them
}