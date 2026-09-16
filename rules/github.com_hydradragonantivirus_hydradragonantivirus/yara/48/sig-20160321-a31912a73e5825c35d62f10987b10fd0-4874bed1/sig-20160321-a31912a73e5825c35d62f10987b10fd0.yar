rule sig_20160321_a31912a73e5825c35d62f10987b10fd0 {
  meta:
    description = "datamaliciousorder - file 20160321_a31912a73e5825c35d62f10987b10fd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3b7942ad7b994ae51efe9f517fe0b8a6b8f813aadec60c4a10b79f00c4a5b78"

  strings:
    $s1  = "return WScript.CreateObject(jdnit);" fullword ascii
    $s2  = "function xMrxceJ(GMJa,sPYwd) {" fullword ascii
    $s3  = "return GMJa.ExpandEnvironmentStrings(sPYwd);" fullword ascii
    $s4  = "return opUzdpf[0] + opUzdpf[2] + opUzdpf[4] + \".F\" + opUzdpf[7] + opUzdpf[9] + opUzdpf[12] + opUzdpf[14];" fullword ascii
    $s5  = "var TU = true  , vSDP = WnT[7] + WnT[9] + WnT[11];" fullword ascii
    $s6  = "var WnT = (\"2.XMLHTTP ypCVJqK UXspj XML ream St KbrnraJR AD FFZoLjb O KRcG D\").split(\" \");" fullword ascii
    $s7  = "var opUzdpf = ePeEt(vqDQXMTGqA+\" \"+\"System wI xzhiQ Obj jnIQjj ect IPeCEAl iboNP\", \" \");" fullword ascii
    $s8  = "LjAvB.open(wlUFh,uDmVD,false);" fullword ascii
    $s9  = "if(H>=R.length) {break;}" fullword ascii
    $s10 = "function RRSheFu(DrQG) {" fullword ascii
    $s11 = "function BCoWi(iDmGOD) {" fullword ascii
    $s12 = "WoK = H; break; " fullword ascii
    $s13 = "function jVrS(tOJml,luPPD) {" fullword ascii
    $s14 = "function twMs(xjblo,vjDew) {" fullword ascii
    $s15 = "function IRLK(KBUTA) {" fullword ascii
    $s16 = "return NaaXA.status;" fullword ascii
    $s17 = "if (d >= JQzVY.length) {break;}" fullword ascii
    $s18 = "function tROH(lLHHN) {" fullword ascii
    $s19 = "return NkY.split(vfAHw);" fullword ascii
    $s20 = "function zVvc(NaaXA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}