rule DCRat_persistence
{
    meta:
        description = "Detects DCRat persistence mechanism strings."
        reference = "NormalStartup.cs"
        
    strings:
                $user = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==" ascii wide
                $admin = "L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g" ascii wide
        
    condition:
        uint16(0) == 0x5A4D and any of them
}