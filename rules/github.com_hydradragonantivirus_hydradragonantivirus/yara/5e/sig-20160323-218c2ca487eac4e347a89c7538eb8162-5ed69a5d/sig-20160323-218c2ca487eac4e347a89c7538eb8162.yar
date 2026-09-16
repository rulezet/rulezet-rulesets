rule sig_20160323_218c2ca487eac4e347a89c7538eb8162 {
  meta:
    description = "datamaliciousorder - file 20160323_218c2ca487eac4e347a89c7538eb8162.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91e276f81b50f024467228990a4b0557e9d5bc58a5c434c4102048b40c82b37c"

  strings:
    $s1  = "return WScript.CreateObject(sXyUO);" fullword ascii
    $s2  = "return CoM.size;" fullword ascii
    $s3  = "var Ry = true  , TBfP = Jbm[7] + Jbm[9] + Jbm[11];" fullword ascii
    $s4  = "return xtEhMjC[0] + xtEhMjC[2] + xtEhMjC[4] + \".F\" + xtEhMjC[7] + xtEhMjC[9] + xtEhMjC[12] + xtEhMjC[14];" fullword ascii
    $s5  = "if (zvCmd > 181965-548){return true;} else {return false;}" fullword ascii
    $s6  = "var Jbm = (\"2.XMLHTTP HheETbG CCTJw XML ream St IDghiWxn AD JpkNejZ O acIG D\").split(\" \");" fullword ascii
    $s7  = "var xtEhMjC = HWbtz(HTVWVbMzHc+\" \"+\"System NH OgJkP Obj PsRSYP ect YEKYjEF bmXJF\", \" \");" fullword ascii
    $s8  = "function UJukkstE(CoM) {" fullword ascii
    $s9  = "function zvrV(zvCmd) {" fullword ascii
    $s10 = "iong.open(qONnm,cBpaC,false);" fullword ascii
    $s11 = "wAF = K; break; " fullword ascii
    $s12 = "function ziMQgvK(pOcn) {" fullword ascii
    $s13 = "return gPblvUS(aP,ZlYhA[481-475]+ZlYhA[562-555]+ZlYhA[504-496]);" fullword ascii
    $s14 = "function xsRgdzCrO(ChIIxGcPtUW) {" fullword ascii
    $s15 = "function gPblvUS(soJv,Ordia) {" fullword ascii
    $s16 = "return new ActiveXObject(nzhJ);" fullword ascii
    $s17 = "function jieF(sXyUO) {" fullword ascii
    $s18 = "return soJv.ExpandEnvironmentStrings(Ordia);" fullword ascii
    $s19 = "if (ItNzb == 901-701){return true;} else {return false;}" fullword ascii
    $s20 = "function LshK(QcreG) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}