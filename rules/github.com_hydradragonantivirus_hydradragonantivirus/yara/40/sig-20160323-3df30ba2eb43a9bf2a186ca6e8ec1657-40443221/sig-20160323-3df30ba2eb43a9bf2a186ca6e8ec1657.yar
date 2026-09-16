rule sig_20160323_3df30ba2eb43a9bf2a186ca6e8ec1657 {
  meta:
    description = "datamaliciousorder - file 20160323_3df30ba2eb43a9bf2a186ca6e8ec1657.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b449048c13bf8381c5522b9262b1e3ad330359aa17bbe772f06283eadf2b601"

  strings:
    $s1  = "return WScript.CreateObject(hAhDd);" fullword ascii
    $s2  = "var GP = true  , bfVW = vvu[7] + vvu[9] + vvu[11];" fullword ascii
    $s3  = "return DUWqGKy[0] + DUWqGKy[2] + DUWqGKy[4] + \".F\" + DUWqGKy[7] + DUWqGKy[9] + DUWqGKy[12] + DUWqGKy[14];" fullword ascii
    $s4  = "var vvu = (\"2.XMLHTTP AgopXPB ckzSi XML ream St tRqfRLFu AD MfdObbr O pWsT D\").split(\" \");" fullword ascii
    $s5  = "ekEc.open(kCBkC,cFofX,false);" fullword ascii
    $s6  = "var DUWqGKy = uDKZG(COudXDgOVH+\" \"+\"System pi DovqN Obj GUzZEp ect NBqJfAK ULIsC\", \" \");" fullword ascii
    $s7  = "return XPig[jttZYl[0]];" fullword ascii
    $s8  = "return emZwAYA(Lv,LtRGU[756-750]+LtRGU[353-346]+LtRGU[233-225]);" fullword ascii
    $s9  = "function hSkg(HTEBM) {" fullword ascii
    $s10 = "if(I>=J.length) {break;}" fullword ascii
    $s11 = "function Zdgg(XsDMa) {" fullword ascii
    $s12 = "function zKkYB(zBRqey) {" fullword ascii
    $s13 = "function emZwAYA(Obxl,CXkDX) {" fullword ascii
    $s14 = "function jFlUv(qnHHuP) {" fullword ascii
    $s15 = "JfX = I; break; " fullword ascii
    $s16 = "return Quw.split(TRMys);" fullword ascii
    $s17 = "function ggWL(hAhDd) {" fullword ascii
    $s18 = "return XsDMa.status;" fullword ascii
    $s19 = "if (yfrxH == 510-310){return true;} else {return false;}" fullword ascii
    $s20 = "if (XcMSg > 191551-848){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}