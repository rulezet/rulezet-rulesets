rule sig_20160313_78edd55443667d9f982e1d69cc4f272d {
  meta:
    description = "datamaliciousorder - file 20160313_78edd55443667d9f982e1d69cc4f272d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3b538261d960b8b0e52421444de50fbda854eda1a35e842bfabd302452a9943"

  strings:
    $s1  = "return HeGfHXi[0] + HeGfHXi[2] + HeGfHXi[4] + \".F\" + HeGfHXi[7] + HeGfHXi[9] + HeGfHXi[12] + HeGfHXi[14];" fullword ascii
    $s2  = "var Bb = true  , GMza = foV[7] + foV[9] + foV[11];" fullword ascii
    $s3  = "CKgwy.open(NuqwD,KfSsd,false);" fullword ascii
    $s4  = "var HeGfHXi = \"Sc GWribxy r jspDwllgj ipting bTlcGih chE ile dQBovvrilGGPUG System BC MIfsQ Obj xmZpwe ect YWiZTag\".split(\" " ascii
    $s5  = "var foV = (\"2.XMLHTTP WKYtbPT XQuxN XML ream St ulJCIwif AD bezKeDr O tYva D\").split(\" \");" fullword ascii
    $s6  = "function jTiMCmd(JEli) {" fullword ascii
    $s7  = "function zAff(lwNxb) {" fullword ascii
    $s8  = "return QHwy.ExpandEnvironmentStrings(mHPCk);" fullword ascii
    $s9  = "function sBLGcklbI() {" fullword ascii
    $s10 = "function IhAQH(lWmgcl) {" fullword ascii
    $s11 = "if(k>=b.length) {break;}" fullword ascii
    $s12 = "if (ZtxoN > 166050-222){return true;} else {return false;}" fullword ascii
    $s13 = "function ymAo(dRqph) {" fullword ascii
    $s14 = "return new ActiveXObject(lWmgcl);" fullword ascii
    $s15 = "function DtkJpRaeb(hgrcIMKcLKS) {" fullword ascii
    $s16 = "function MteI(HQaDX) {" fullword ascii
    $s17 = "function pZqOAQGi(GAe) {" fullword ascii
    $s18 = "function BiMR(PgwKK,JYdhH) {" fullword ascii
    $s19 = "return lwNxb.status;" fullword ascii
    $s20 = "if (L >= HySQg.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}