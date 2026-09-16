rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oUJio_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdc6f9b3a71195d1fc9e71a6b0d1d41f18577402fbbdf4f6a11a43a70efef6ef"

  strings:
    $s1  = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****: CALLBACKS VALIDATION FAILURE (HALDDMiscellaneous2): no GetDriverState suppor" ascii
    $s2  = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****:Pre DX7 Driver should report clear2 if any stencilcaps are set, failing drive" ascii
    $s3  = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****:Actual size reported is not equal to dwSize field in the Extended caps struct" ascii
    $s4  = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****: CALLBACKS VALIDATION FAILURE (D3DCallbacks2): must export all or none of Dra" ascii
    $s5  = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****:Driver gives too big a size for DDMORESURFACECAPS. Check the dwSize calculati" ascii
    $s6  = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****: CALLBACKS VALIDATION FAILURE (ColorControl): Driver overwrote callbacks buff" ascii
    $s7  = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****: CALLBACKS VALIDATION FAILURE (D3DCallbacks2): Driver overwrote callbacks buf" ascii
    $s8  = "r creation" fullword ascii
    $s9  = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****: CALLBACKS VALIDATION FAILURE (D3DCallbacks3): no ValidateTextureStageState s" ascii
    $s10 = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****: CALLBACKS VALIDATION FAILURE (D3DCallbacks3): Driver overwrote callbacks buf" ascii
    $s11 = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****: CALLBACKS VALIDATION FAILURE (Miscellaneous2): Driver overwrote callbacks bu" ascii
    $s12 = "****DirectDraw/Direct3D DRIVER DISABLING ERROR****: CALLBACKS VALIDATION FAILURE (Miscellaneous): Driver overwrote callbacks buf" ascii
    $s13 = "invalid CAPS flags: DDSCAPS_COMPLEX requires at least one of DDSCAPS_BACKBUFFER/DDSCAPS_OFFSCREENPLAIN/DDSCAPS_OVERLAY/DDSCAPS_T" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}