rule sig_20160323_e27d03724c0557557168d563f891d830 {
  meta:
    description = "datamaliciousorder - file 20160323_e27d03724c0557557168d563f891d830.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7567803d691568aaa0936a8f0ccd1ed47d462c0ff11aac4c181adb7bc467a5a1"

  strings:
    $s1  = "return WScript.CreateObject(PWeGz);" fullword ascii
    $s2  = "return jfkCEjJ[0] + jfkCEjJ[2] + jfkCEjJ[4] + \".F\" + jfkCEjJ[7] + jfkCEjJ[9] + jfkCEjJ[12] + jfkCEjJ[14];" fullword ascii
    $s3  = "var qM = true  , poNs = heF[7] + heF[9] + heF[11];" fullword ascii
    $s4  = "var heF = (\"2.XMLHTTP BJGfEre JiTNh XML ream St eVnYEhKv AD mkyhkLY O BxfE D\").split(\" \");" fullword ascii
    $s5  = "GiVA.open(mmInS,OkABa,false);" fullword ascii
    $s6  = "var jfkCEjJ = RKhKd(ujYLKEqkxX+\" \"+\"System PW GhJwB Obj nJSlxK ect jpWtIBk DvwMh\", \" \");" fullword ascii
    $s7  = "return EVYL.ExpandEnvironmentStrings(eFBbV);" fullword ascii
    $s8  = "function lCmo(SpnCE,fflHt) {" fullword ascii
    $s9  = "if (EoaoX == 614-414){return true;} else {return false;}" fullword ascii
    $s10 = "if (Z >= PrHrQ.length) {break;}" fullword ascii
    $s11 = "function Blmh(jysqr,CtynI) {" fullword ascii
    $s12 = "function GbkEq(uZbbFQ) {" fullword ascii
    $s13 = "function Rafd(ENztG) {" fullword ascii
    $s14 = "function RKhKd(wCq,jMTPx) {" fullword ascii
    $s15 = "return hLHDYau(HT,hiDRO[938-932]+hiDRO[126-119]+hiDRO[108-100]);" fullword ascii
    $s16 = "if(d>=k.length) {break;}" fullword ascii
    $s17 = "function Plur(pZYTn) {" fullword ascii
    $s18 = "return uZbbFQ/*d3tCvFzUtupwCX288SOhF7tQk*/.position=726-726;" fullword ascii
    $s19 = "return JsxFV.status;" fullword ascii
    $s20 = "function OrJX(PWeGz) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}