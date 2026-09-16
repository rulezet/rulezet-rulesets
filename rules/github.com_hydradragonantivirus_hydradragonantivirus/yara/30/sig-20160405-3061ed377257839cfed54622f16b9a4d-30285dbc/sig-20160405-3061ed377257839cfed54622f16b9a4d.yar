rule sig_20160405_3061ed377257839cfed54622f16b9a4d {
  meta:
    description = "datamaliciousorder - file 20160405_3061ed377257839cfed54622f16b9a4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21cc1702460dd488ddf0914dee459fca02a4828c730de7c660d1818aae090fbb"

  strings:
    $s1  = "return ApEAobw[0] + ApEAobw[2] + ApEAobw[4] + \".F\" + ApEAobw[7] + ApEAobw[9] + ApEAobw[12] + ApEAobw[14];" fullword ascii
    $s2  = "var Be = true  , qFwK = oTz[7] + oTz[9] + oTz[11];" fullword ascii
    $s3  = "var oTz = (\"2.XMLHTTP NOxnbbW jeHST XML ream St xofzcUmE AD GbIDaSC O kuKy D\").split(\" \");" fullword ascii
    $s4  = "var ulskbzw = \"FRpUoJ*Omk*pt.S\"+\"hell*SjYSiHD*Scri*\";" fullword ascii
    $s5  = "if (V >= BlFSe.length) {break;}" fullword ascii
    $s6  = "function hCIrRLI(tiXR,WparF) {" fullword ascii
    $s7  = "function VJQD(cowrm) {" fullword ascii
    $s8  = "function mRduexIqE(EghXkmVyZGk) {" fullword ascii
    $s9  = "function dWMj(KTLYY) {" fullword ascii
    $s10 = "return hCIrRLI(Zi,mryiB[586-580]+mryiB[921-914]+mryiB[428-420]);" fullword ascii
    $s11 = "function WRlbB(mjEEILTq,fywd) {" fullword ascii
    $s12 = "return new ActiveXObject(FstY);" fullword ascii
    $s13 = "return QhWJ;" fullword ascii
    $s14 = "function ITBUSq(SaiT,sZQIfP) {" fullword ascii
    $s15 = "function nHwk(BlFSe) {" fullword ascii
    $s16 = "function UxbI(PzeOC) {" fullword ascii
    $s17 = "if (cowrm == 397-197){return true;} else {return false;}" fullword ascii
    $s18 = "function WBts(SGhEI,VhKjY) {" fullword ascii
    $s19 = "function oJqg(osofe) {" fullword ascii
    $s20 = "function pqGxY(jmy,EsFUB) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}