rule sig_20160303_4d47441aa33fe1ef522a0f24e74d7313 {
  meta:
    description = "datamaliciousorder - file 20160303_4d47441aa33fe1ef522a0f24e74d7313.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b93cea9ea9ac3e8e515654feac0390863b7ed2bc61c9b9bd5d17b39836a4e5c7"

  strings:
    $s1  = "var zZ = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(oajGQ);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + GdLmGOB + \".F\" + JgjciXbnBA + QMjGh + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var Lx = true  , BYau = HFr[7] + \"\" + HFr[9];" fullword ascii
    $s5  = "var HFr = (nln + \"TTP\" + \" OlABrsb WazbH XML ream St ZoQuKwvj AD sXTfGqa OD\").split(\" \");" fullword ascii
    $s6  = "mRXKn.open(ejNXD,pmkPw,false);" fullword ascii
    $s7  = "if(w>=f.length) {break;}" fullword ascii
    $s8  = "return zO.ExpandEnvironmentStrings(zZ);" fullword ascii
    $s9  = "function RlUNeQsGw(HbCtkmOdBAc) {" fullword ascii
    $s10 = "function TawZ(qMKpc) {" fullword ascii
    $s11 = "function gdhHc(uwtdIS) {" fullword ascii
    $s12 = "function kjmutpH(BZoO) {" fullword ascii
    $s13 = "function Tjqg(xraNz,kDVVg) {" fullword ascii
    $s14 = "return dlBDv;" fullword ascii
    $s15 = "function LGDi(pWToy) {" fullword ascii
    $s16 = "function jfVqOiMi() {" fullword ascii
    $s17 = "if (((new Date())>0,7291890888)) {" fullword ascii
    $s18 = "return new ActiveXObject(uwtdIS);" fullword ascii
    $s19 = "function CkFX(duvHL) {" fullword ascii
    $s20 = "function tzVX(oajGQ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}