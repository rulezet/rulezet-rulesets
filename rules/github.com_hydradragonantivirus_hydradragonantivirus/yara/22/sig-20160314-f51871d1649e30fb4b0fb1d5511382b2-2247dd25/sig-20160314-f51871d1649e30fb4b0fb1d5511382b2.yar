rule sig_20160314_f51871d1649e30fb4b0fb1d5511382b2 {
  meta:
    description = "datamaliciousorder - file 20160314_f51871d1649e30fb4b0fb1d5511382b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8240aa56fadb3064f07401682f4b6912e7ced7ad05d4727b8973b7468ea5e2cd"

  strings:
    $s1  = "var Fd = true  , iqHI = Iun[7] + Iun[9] + Iun[11];" fullword ascii
    $s2  = "return NwcKLcu[0] + NwcKLcu[2] + NwcKLcu[4] + \".F\" + NwcKLcu[7] + NwcKLcu[9] + NwcKLcu[12] + NwcKLcu[14];" fullword ascii
    $s3  = "BPhDM.open(yVFKq,WDvPF,false);" fullword ascii
    $s4  = "var Iun = (\"2.XMLHTTP lpUOdne aYCUR XML ream St XHDbJUss AD EtELbrW O kNfz D\").split(\" \");" fullword ascii
    $s5  = "if(S>=a.length) {break;}" fullword ascii
    $s6  = "return RQT.size;" fullword ascii
    $s7  = "function YNQx(yzovO) {" fullword ascii
    $s8  = "function quQm(gPUAb) {" fullword ascii
    $s9  = "function TVbq(cXcqa) {" fullword ascii
    $s10 = "function VtMbQMG(XXfx,APJRy) {" fullword ascii
    $s11 = "if (yzovO == 791-591){return true;} else {return false;}" fullword ascii
    $s12 = "function WmvW(Nvacl) {" fullword ascii
    $s13 = "function hJKm(FOBRL,uBgyW) {" fullword ascii
    $s14 = "function YIPY(BPhDM,WDvPF,yVFKq) {" fullword ascii
    $s15 = "return new ActiveXObject(PyaGKv);" fullword ascii
    $s16 = "return XXfx.ExpandEnvironmentStrings(APJRy);" fullword ascii
    $s17 = "function xGwEuXmZd() {" fullword ascii
    $s18 = "return sXRs.responseBody;" fullword ascii
    $s19 = "if (NAjxy > 190912-587){return true;} else {return false;}" fullword ascii
    $s20 = "function YNBtoPtw() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}