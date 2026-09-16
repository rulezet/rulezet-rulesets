rule sig_20160404_e0231c263561288d8a573d438581f98c {
  meta:
    description = "datamaliciousorder - file 20160404_e0231c263561288d8a573d438581f98c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5f8fdd75dca35790a7dad467c34ec6f473f40bc83620b1430e34b179c9e44b2"

  strings:
    $s1  = "return bIqFSHu[0] + bIqFSHu[2] + bIqFSHu[4] + \".F\" + bIqFSHu[7] + bIqFSHu[9] + bIqFSHu[12] + bIqFSHu[14];" fullword ascii
    $s2  = "var tG = true  , AJZQ = chG[7] + chG[9] + chG[11];" fullword ascii
    $s3  = "vaPV.open(xRNWz,Xnotk,false);" fullword ascii
    $s4  = "var bIqFSHu = XaCKE(ZPUAoIeyPR+\" \"+\"System Jt Sauec Obj PLcwzo ect TuCJjdf VtWsu\", \" \");" fullword ascii
    $s5  = "var chG = (\"2.XMLHTTP YGbJRJK MAMtX XML ream St PfuaVSgC AD vrGEbMV O AIpQ D\").split(\" \");" fullword ascii
    $s6  = "function DBGsQfVb(EaH) {" fullword ascii
    $s7  = "function uTOkAsNnm(vtblK) {" fullword ascii
    $s8  = "function RLFO(SSDFx) {" fullword ascii
    $s9  = "function JiRV(DelLd) {" fullword ascii
    $s10 = "return liHykHp;" fullword ascii
    $s11 = "if (SVZza > 161971-495){return true;} else {return false;}" fullword ascii
    $s12 = "return aatiM;" fullword ascii
    $s13 = "return EaH.size;" fullword ascii
    $s14 = "function XIfWGB(DNsv,lNiQaf) {" fullword ascii
    $s15 = "var kpIwLRN = \"pHwcrH*bGN*pt.S\"+\"hell*DeEEyMh*Scri*\";" fullword ascii
    $s16 = "function loVVI(rFmGgLnw,NaPv) {" fullword ascii
    $s17 = "return new ActiveXObject(EQJh);" fullword ascii
    $s18 = "return NQemsoa(XX,kujFP[324-318]+kujFP[380-373]+kujFP[205-197]);" fullword ascii
    $s19 = "gLU = H; break; " fullword ascii
    $s20 = "return NhGvy.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}