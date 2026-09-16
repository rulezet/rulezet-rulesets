rule sig_20160310_87da76829a2aeb014d4bb6395822dc28 {
  meta:
    description = "datamaliciousorder - file 20160310_87da76829a2aeb014d4bb6395822dc28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c106962c7515b670d45c73d85b437b25e7f17904d994f7b090f94291b1f6aceb"

  strings:
    $s1  = "function aUijiRc(fxKM) {" fullword ascii
    $s2  = "var qC = true  , ABSl = DPF[7] + DPF[9] + DPF[11];" fullword ascii
    $s3  = "return EVWFLuv[0] + EVWFLuv[2] + EVWFLuv[4] + \".F\" + EVWFLuv[7] + EVWFLuv[9] + EVWFLuv[12] + EVWFLuv[14];" fullword ascii
    $s4  = "jbUst.open(aOzqH,dyiiT,false);" fullword ascii
    $s5  = "var DPF = (\"2.XMLHTTP lgSvQTW vpkQC XML ream St nRkBNGtH AD OtEAjkt O wzoo D\").split(\" \");" fullword ascii
    $s6  = "var EVWFLuv = \"Sc pGQWwSh r pyAznvdCc ipting QgvkCFW Ijw ile fVqauHRmisvAII System mb XvwCr Obj URnsAU ect ekdhzFb\".split(\" " ascii
    $s7  = "function QACk(hEYGL) {" fullword ascii
    $s8  = "function pMZkQxaU() {" fullword ascii
    $s9  = "function MoDr(DtGUD,KrpCV) {" fullword ascii
    $s10 = "return QEdZmFi" fullword ascii
    $s11 = "function oFyQfmsC(OagQL,DBXPts) {" fullword ascii
    $s12 = "function ejBu(eHXgQ) {" fullword ascii
    $s13 = "function SNEJ(jbUst,dyiiT,aOzqH) {" fullword ascii
    $s14 = "return fxKM.responseBody;" fullword ascii
    $s15 = "function bPav(ODfAy) {" fullword ascii
    $s16 = "function hcZE(OVZfd) {" fullword ascii
    $s17 = "function INpxg(NsrcvE) {" fullword ascii
    $s18 = "if(S>=J.length) {break;}" fullword ascii
    $s19 = "vsH = S; break; " fullword ascii
    $s20 = "if (eHXgQ > 187431-786){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}