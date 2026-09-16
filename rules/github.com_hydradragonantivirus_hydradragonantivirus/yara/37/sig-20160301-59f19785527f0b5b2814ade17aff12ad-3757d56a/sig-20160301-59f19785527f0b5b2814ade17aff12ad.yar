rule sig_20160301_59f19785527f0b5b2814ade17aff12ad {
  meta:
    description = "datamaliciousorder - file 20160301_59f19785527f0b5b2814ade17aff12ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b639a9a6e81c4da41b65771c72de01bf210004ed9eb902c049730745d7eb45f6"

  strings:
    $s1  = "var zN = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(yYUpT);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + JHBZriB + \".F\" + RhQKQmiXNO + QJlyz + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var XqJ = (jUM + \"TTP\" + \" IylIvZX OpPSn XML ream St ZFVgCsAq AD GkxVYAo OD\").split(\" \");" fullword ascii
    $s5  = "var bt = true  , dalf = XqJ[7] + \"\" + XqJ[9];" fullword ascii
    $s6  = "XDAJK.open(mNYqf,hiTGD,false);" fullword ascii
    $s7  = "function wkeY(kQygy,BrEBc) {" fullword ascii
    $s8  = "function ztHa(kFwwU) {" fullword ascii
    $s9  = "function JwPi(beQyN,JOBBd) {" fullword ascii
    $s10 = "function QLZG(MICeM) {" fullword ascii
    $s11 = "return RI.ExpandEnvironmentStrings(zN);" fullword ascii
    $s12 = "return OxrQU.status;" fullword ascii
    $s13 = "if (yHfUa == 700-500){return true;} else {return false;}" fullword ascii
    $s14 = "function vwgI(yHfUa) {" fullword ascii
    $s15 = "if (kFwwU > 173654-608){return true;} else {return false;}" fullword ascii
    $s16 = "function AGRN(Yakpf) {" fullword ascii
    $s17 = "function XTmV(yYUpT) {" fullword ascii
    $s18 = "function PlEy(XDAJK,hiTGD,mNYqf) {" fullword ascii
    $s19 = "function Loei(umCUm) {" fullword ascii
    $s20 = "qpX = q; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}