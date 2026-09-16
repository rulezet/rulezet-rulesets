rule sig_20160312_13290702ada15043b28bc76bde40276c {
  meta:
    description = "datamaliciousorder - file 20160312_13290702ada15043b28bc76bde40276c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82fc3d3f644a48ec11b12bc02e330e1dbca4a0d0e8b3757724209bd269631e8e"

  strings:
    $s1  = "var IM = true  , qqkb = UWN[7] + UWN[9] + UWN[11];" fullword ascii
    $s2  = "return StQRXZI[0] + StQRXZI[2] + StQRXZI[4] + \".F\" + StQRXZI[7] + StQRXZI[9] + StQRXZI[12] + StQRXZI[14];" fullword ascii
    $s3  = "var StQRXZI = \"Sc skKETBw r pWahzuNTk ipting TiqqLxu bXK ile ZwiFiJHPcMURhj System HX gmCuX Obj wJLhbe ect KlDtkjY\".split(\" " ascii
    $s4  = "BXrgg.open(MEkyn,XDqVY,false);" fullword ascii
    $s5  = "var UWN = (\"2.XMLHTTP oMyAsAA yzGma XML ream St qIZPysjy AD fGlrSxt O KcDA D\").split(\" \");" fullword ascii
    $s6  = "if (J >= CsHrh.length) {break;}" fullword ascii
    $s7  = "return PNK.size;" fullword ascii
    $s8  = "function jVAiImJfj() {" fullword ascii
    $s9  = "function ckZKKtwt(PNK) {" fullword ascii
    $s10 = "return RuTnumQ" fullword ascii
    $s11 = "return Cfvh.ExpandEnvironmentStrings(NHZMe);" fullword ascii
    $s12 = "return UFDRBM.position=760-760;" fullword ascii
    $s13 = "function ciYL(AGxiM) {" fullword ascii
    $s14 = "return amOjB.status;" fullword ascii
    $s15 = "function gOcww(obTBYY) {" fullword ascii
    $s16 = "function EHMk(BXrgg,XDqVY,MEkyn) {" fullword ascii
    $s17 = "function RKcV(KpXsv) {" fullword ascii
    $s18 = "function pJlF(CsHrh) {" fullword ascii
    $s19 = "if(C>=Q.length) {break;}" fullword ascii
    $s20 = "function FAAl(hsNHI) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}