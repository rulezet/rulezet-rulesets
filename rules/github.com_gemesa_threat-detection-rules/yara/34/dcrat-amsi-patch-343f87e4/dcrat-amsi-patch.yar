rule DCRat_AMSI_patch
{
    meta:
        description = "Detects AMSI patch shellcode bytes."
        reference = "Amsi.cs"
        
    strings:
        
        $patch_x64 = { B8 57 00 07 80 C3 }
        $patch_x86 = { B8 57 00 07 80 C2 18 00 }
        $patch_b64_x64 = "uFcAB4DD" ascii wide
        $patch_b64_x86 = "uFcAB4DCGAA=" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and any of them
}