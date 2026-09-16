rule sig_20160323_f0e101c81f86ca4f5f4a384dc1298e7a {
  meta:
    description = "datamaliciousorder - file 20160323_f0e101c81f86ca4f5f4a384dc1298e7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee713823e54fa5c801c362c5168e8e71162083f959fc9228e57f42910d7ed204"

  strings:
    $s1  = "return WScript.CreateObject(zJpsR);" fullword ascii
    $s2  = "return dgsyjhC[0] + dgsyjhC[2] + dgsyjhC[4] + \".F\" + dgsyjhC[7] + dgsyjhC[9] + dgsyjhC[12] + dgsyjhC[14];" fullword ascii
    $s3  = "var UF = true  , KWRi = Wgx[7] + Wgx[9] + Wgx[11];" fullword ascii
    $s4  = "iAXX.open(pUvFE,wjfJR,false);" fullword ascii
    $s5  = "var dgsyjhC = YrYVe(hDzePITVPG+\" \"+\"System nG tvAKC Obj OuysWv ect jrXTZXT WjTVG\", \" \");" fullword ascii
    $s6  = "var Wgx = (\"2.XMLHTTP lDvcDdQ grBkx XML ream St lUhNCnhq AD DDAEXEH O GFdx D\").split(\" \");" fullword ascii
    $s7  = "function VZHu(AXjEv,wjfJR,pUvFE) {" fullword ascii
    $s8  = "function VxsQt(bjAgeA) {" fullword ascii
    $s9  = "return naySrMb(eY,jfyBR[485-479]+jfyBR[930-923]+jfyBR[430-422]);" fullword ascii
    $s10 = "function YrYVe(Sxb,eiaEs) {" fullword ascii
    $s11 = "return qHzMl.status;" fullword ascii
    $s12 = "function NhOxk(PPUyZz) {" fullword ascii
    $s13 = "return DyDw[xbulFF[0]];" fullword ascii
    $s14 = "function bjwHsPBh(sTIb) {" fullword ascii
    $s15 = "function KUxeTMQr(Tjw) {" fullword ascii
    $s16 = "function SJTO(vbOJZ) {" fullword ascii
    $s17 = "if(m>=G.length) {break;}" fullword ascii
    $s18 = "function UsqL(kTLfO) {" fullword ascii
    $s19 = "return new ActiveXObject(uDZv);" fullword ascii
    $s20 = "if (vbOJZ == 751-551){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}