rule _Virus_Autorun_Gen_Heur_Mint_Autorunner_1_Virus_Autorun_Gen_Vari_110 {
  meta:
    description = "datamaliciousorder - from files Virus.Autorun_Gen.Heur.Mint.Autorunner.1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_1.vir, Virus.Autorun_Gen.Variant.Application.Barys.1471_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_15_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_14_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_12_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_233_1.vir, VirusShareTrojanVbCrypt250_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aefdc6da05cfd4012097251989683d30f21626362c29463da121dc621046b2b6"
    hash2       = "36bbc80169bd128d160fb3869dcf23891b69a7765d8abb171897c9dfd0d58e3a"
    hash3       = "0ea76f5343284061fe91a1363d0a2116b76db249e7de5cc17a6971f30f805011"
    hash4       = "c25118c87134ffa298b9ec21b6abbfb10ced5f41dee519e34b593db27e0ce502"
    hash5       = "940de455f281b3225827ecddd883f1b43ba1368dbd7f57716d0a339045f24379"
    hash6       = "838086ed8b4207c84b7c179a283d8cfe128e7e3c50a0073d96c26764f782742d"
    hash7       = "b9b6d8d4e5e6cd4b77e5a6c7210788216aa3bb117891716f5015552052351ce2"
    hash8       = "a5dfab92bc0fe88046376c003f550774217c4668c8d766ded7b45a5d3fd4eab0"
    hash9       = "4f08e3a69121dfc3731f51c33e40cb14ff28c745c3471bd8ec1328cb7426f648"
    hash10      = "b35021f76bf0585b970e2be0716dae07652242bae8affb1ee54288b367312a8b"
    hash11      = "25580ea287f391443b3f34e0d22069b5b1739b6312c794f7f97a82c0c4488470"
    hash12      = "4e62e7a3b77d4d0abb803c175f51d1242fda33bfd3308991b9e90391cac1c369"
    hash13      = "30f2f4066055982aa217e1da873c8c5306b812730a14c821c3dca50fec8f4fef"
    hash14      = "81f62aa60559e7596bfb8a5ff524e78623fa29e89f07b3f8e9b683132dc9ffb0"

  strings:
    $s1  = "SkippingQPC failed - falling back to timeGetTime()" fullword wide
    $s2  = "Couldn't get wma output count for file: %s - %08x (%s)" fullword wide
    $s3  = "Sound file wave format header is incorrect size: %s - %08x (%s)" fullword wide
    $s4  = "Couldn't get WMHeaderInfn for file: %s - %08x (%s)" fullword wide
    $s5  = "Couldn't get duration attribute: %s - %08x (%s)" fullword wide
    $s6  = "Resource Id %d could not be found -- either failed to page in or invalid handle." fullword wide
    $s7  = "DDS loader currently only supports the RGB format A8R8G8B8" fullword wide
    $s8  = "DDS loader currently only supports the FOURCC formats DXT1, DXT3, and DXT5" fullword wide
    $s9  = "Cannot create render target, format: %d, hr %x(%s)" fullword wide
    $s10 = "Cannot creata render target 2, format: %d, hr %x(%s)" fullword wide
    $s11 = "SetResolution() -- failure in RecreateDefaultResources()" fullword wide
    $s12 = "Could not create node from type - type %s not found" fullword wide
    $s13 = "Monitor is small compared to the window - requesting maximize." fullword wide
    $s14 = "Couldn't open wma stream for file: %s - %08x (%s)" fullword wide
    $s15 = "Couldn't set wma range for file: %s - %08x (%s)" fullword wide
    $s16 = "File is not audio: %s - %08x (%s)" fullword wide
    $s17 = "Audio formattype is not wave format ex: %s - %08x (%s)" fullword wide
    $s18 = "Invalid font ID passed to GetTextSize (%d)" fullword wide
    $s19 = "No parent accessible node found on import - this is very bad" fullword wide
    $s20 = "Error reading tga header from %s" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}