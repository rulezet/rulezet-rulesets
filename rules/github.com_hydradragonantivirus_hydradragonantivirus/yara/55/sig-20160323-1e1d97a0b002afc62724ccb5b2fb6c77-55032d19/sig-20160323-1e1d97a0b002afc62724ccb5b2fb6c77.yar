rule sig_20160323_1e1d97a0b002afc62724ccb5b2fb6c77 {
  meta:
    description = "datamaliciousorder - file 20160323_1e1d97a0b002afc62724ccb5b2fb6c77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "821a1107aa72479817f0271c99421c56eba3b3ce545f90e9807f429770e1670f"

  strings:
    $s1  = "return WScript.CreateObject(cqSXK);" fullword ascii
    $s2  = "var NH = true  , WJeg = ecV[7] + ecV[9] + ecV[11];" fullword ascii
    $s3  = "return jJMZsyB[0] + jJMZsyB[2] + jJMZsyB[4] + \".F\" + jJMZsyB[7] + jJMZsyB[9] + jJMZsyB[12] + jJMZsyB[14];" fullword ascii
    $s4  = "var jJMZsyB = JuEDc(AyspqqFhcn+\" \"+\"System Zl ufsxd Obj ynlUih ect vTCrech FDyGp\", \" \");" fullword ascii
    $s5  = "QvwL.open(YiOCG,GnsaU,false);" fullword ascii
    $s6  = "var ecV = (\"2.XMLHTTP cVDjdyX oiJPt XML ream St qNrcGoUF AD MsCVjiR O TvGC D\").split(\" \");" fullword ascii
    $s7  = "return DjC.size;" fullword ascii
    $s8  = "return Ckj.split(xgVVS);" fullword ascii
    $s9  = "if (WHkEu == 339-139){return true;} else {return false;}" fullword ascii
    $s10 = "function FuRlshsf(ZxvZ) {" fullword ascii
    $s11 = "function otHU(cqSXK) {" fullword ascii
    $s12 = "function WgqOO(pQMceT) {" fullword ascii
    $s13 = "function DQig(gyVgs) {" fullword ascii
    $s14 = "if (F >= dVyRl.length) {break;}" fullword ascii
    $s15 = "PCH = Q; break; " fullword ascii
    $s16 = "function tVPm(dVyRl) {" fullword ascii
    $s17 = "function JuEDc(Ckj,xgVVS) {" fullword ascii
    $s18 = "function hefbi(cqVIlD) {" fullword ascii
    $s19 = "if(Q>=i.length) {break;}" fullword ascii
    $s20 = "return rHMIUQX(FQ,zEBXN[453-447]+zEBXN[174-167]+zEBXN[519-511]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}