rule sig_20160301_0dc3bf91344f54e2b7b5ca387a8f55b5 {
  meta:
    description = "datamaliciousorder - file 20160301_0dc3bf91344f54e2b7b5ca387a8f55b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f96c8f27039c7cce5cf33a5aa0b36bdd18e87186fc318865e2428206c5599db"

  strings:
    $s1  = "var Gk = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(imumB);" fullword ascii
    $s3  = "var PVo = (Cdk + \"TTP\" + \" qrdKixY yufRR XML ream St tpRdoTVk AD ZPRWRnX OD\").split(\" \");" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + xAcDuWW + \".F\" + grQibGokBt + xJpUs + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var ua = true  , Laak = PVo[7] + \"\" + PVo[9];" fullword ascii
    $s6  = "NJfpu.open(suJDl,eKPkH,false);" fullword ascii
    $s7  = "function VgxFwAHCr(PtUAL,LlFXs,FlysN) {" fullword ascii
    $s8  = "if (ugtoW > 170089-579){return true;} else {return false;}" fullword ascii
    $s9  = "return VOEVr;" fullword ascii
    $s10 = "if(O>=m.length) {break;}" fullword ascii
    $s11 = "function OdqYYdyX() {" fullword ascii
    $s12 = "function eWoi(imumB) {" fullword ascii
    $s13 = "VWV = O; break; " fullword ascii
    $s14 = "function eaom(RCxQE) {" fullword ascii
    $s15 = "function inRYegGzC(GJaRFJrtZko) {" fullword ascii
    $s16 = "return pt.ExpandEnvironmentStrings(Gk);" fullword ascii
    $s17 = "function BCqs(tiLfc,OztrY) {" fullword ascii
    $s18 = "return TIMdT.status;" fullword ascii
    $s19 = "function DKdw(ReLQG) {" fullword ascii
    $s20 = "function qdXC(NJfpu,eKPkH,suJDl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}