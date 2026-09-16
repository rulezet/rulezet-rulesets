rule sig_20160310_b2f0b6d10eb32513c7f0a5d04311a733 {
  meta:
    description = "datamaliciousorder - file 20160310_b2f0b6d10eb32513c7f0a5d04311a733.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b3a7ad9b229ea63a570951a9a916943746f99997bcb647c6b1fa1f15b61c10b"

  strings:
    $s1  = "function wPMl(hEadV) {" fullword ascii
    $s2  = "var dx = true  , LlAA = Jte[7] + Jte[9] + Jte[11];" fullword ascii
    $s3  = "return bckFVHl[0] + bckFVHl[2] + bckFVHl[4] + \".F\" + bckFVHl[7] + bckFVHl[9] + bckFVHl[12] + bckFVHl[14];" fullword ascii
    $s4  = "var Jte = (\"2.XMLHTTP lxsGWYS uosKm XML ream St qjtSytgT AD TJHPZCN O uruw D\").split(\" \");" fullword ascii
    $s5  = "var bckFVHl = \"Sc CUCunET r IMvmUWlDQ ipting YgExKvu cUF ile pxtJwMgCsUDDBm System eF yAqgx Obj mKOXuj ect mmPCyFs\".split(\" " ascii
    $s6  = "ehlnH.open(ALeGs,CnUkw,false);" fullword ascii
    $s7  = "if(t>=G.length) {break;}" fullword ascii
    $s8  = "if (u >= Guqvs.length) {break;}" fullword ascii
    $s9  = "function fqrDXuCt(hauFI,CFSHVc) {" fullword ascii
    $s10 = "function fipPu(BEUtKT) {" fullword ascii
    $s11 = "return Enu.size;" fullword ascii
    $s12 = "function ZhQF(Guqvs) {" fullword ascii
    $s13 = "YrT = t; break; " fullword ascii
    $s14 = "return new ActiveXObject(UkpNuZ);" fullword ascii
    $s15 = "function pdnL(NkojE) {" fullword ascii
    $s16 = "function klfIUszV(Enu) {" fullword ascii
    $s17 = "function UbWR(auIAA) {" fullword ascii
    $s18 = "function ZEQs(zhLyd,sTTMy) {" fullword ascii
    $s19 = "return DuJqO;" fullword ascii
    $s20 = "if (DSLLn == 381-181){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}