rule DCRat_AMSI_bypass
{
    meta:
        description = "Detects base64 encoded AMSI bypass strings."
        reference = "Amsi.cs"
        
    strings:
                $amsi_dll = "YW1zaS5kbGw=" ascii wide
                $amsi_func = "QW1zaVNjYW5CdWZmZXI=" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and all of them
}