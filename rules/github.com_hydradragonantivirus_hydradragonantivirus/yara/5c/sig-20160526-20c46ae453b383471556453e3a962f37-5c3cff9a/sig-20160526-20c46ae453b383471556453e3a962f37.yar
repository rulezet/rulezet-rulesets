rule sig_20160526_20c46ae453b383471556453e3a962f37 {
  meta:
    description = "datamaliciousorder - file 20160526_20c46ae453b383471556453e3a962f37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcad7400d483777691c35ddfcbc2fc901c3daca891937149ab99e1eaec0e5385"

  strings:
    $s1  = "function FtlAQ(OLHtiqgnoTZTg) {var KMFyrrDl = RfVHcnFdg.join(FbEzXEGNlPCjsUQEtXPhsPxc[0]);var wwxbOqjSHefDcgttvaXiQCaC, FpsyKpPS" ascii
    $s2  = "2), 2) - 1))-27)) HmiYtYIRlOB += As(wwxbOqjSHefDcgttvaXiQCaC);else if (pdYLVhwIjpZ == (904 + Math.round((Math.pow(Math.sin(67), " ascii
    $s3  = "2) + Math.pow(Math.cos(67), 2) - 1))-840)) HmiYtYIRlOB += jVEIOky(wwxbOqjSHefDcgttvaXiQCaC, FpsyKpPSetLqx);else HmiYtYIRlOB += u" ascii
    $s4  = "function ISzJWEUdSpPfgAArCYTujxK(uEcODhX,eFhxWCYSLUdTa){return uEcODhX.charAt(eFhxWCYSLUdTa);}" fullword ascii
    $s5  = "function uTJyTDFovKE(GbEipOyLk,mYfELblcRgPFLMevxEyfvw,YNIKWdhIBgajgvnnWYcyO){return String.fromCharCode(GbEipOyLk,mYfELblcRgPFLM" ascii
    $s6  = "function uTJyTDFovKE(GbEipOyLk,mYfELblcRgPFLMevxEyfvw,YNIKWdhIBgajgvnnWYcyO){return String.fromCharCode(GbEipOyLk,mYfELblcRgPFLM" ascii
    $s7  = "function As(RizOQJ){return String.fromCharCode(RizOQJ);}" fullword ascii
    $s8  = "function PNpXuDPUVFQsWJiyeqP(IAVMG,CMzBlUudSy){return IAVMG.indexOf(CMzBlUudSy);}" fullword ascii
    $s9  = "function jVEIOky(YoWsiywIMzqW,uoMqIuomRSHzawVqgXBr){return String.fromCharCode(YoWsiywIMzqW,uoMqIuomRSHzawVqgXBr);}" fullword ascii
    $s10 = "function FtlAQ(OLHtiqgnoTZTg) {var KMFyrrDl = RfVHcnFdg.join(FbEzXEGNlPCjsUQEtXPhsPxc[0]);var wwxbOqjSHefDcgttvaXiQCaC, FpsyKpPS" ascii
    $s11 = "TJyTDFovKE(wwxbOqjSHefDcgttvaXiQCaC, FpsyKpPSetLqx, JQMNKrNSfPq);} while (dIltQIvmaUTevdX < OLHtiqgnoTZTg.length);return HmiYtYI" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}