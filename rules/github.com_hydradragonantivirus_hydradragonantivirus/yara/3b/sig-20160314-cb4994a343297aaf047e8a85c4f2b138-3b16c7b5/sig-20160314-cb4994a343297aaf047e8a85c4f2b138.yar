rule sig_20160314_cb4994a343297aaf047e8a85c4f2b138 {
  meta:
    description = "datamaliciousorder - file 20160314_cb4994a343297aaf047e8a85c4f2b138.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79b09bda45123daae87fc5e48504e47f6ebd2f36707e0c86fcb5fcbea1f0f3f7"

  strings:
    $s1  = "var Db = true  , ylCg = daT[7] + daT[9] + daT[11];" fullword ascii
    $s2  = "return rBNhIaR[0] + rBNhIaR[2] + rBNhIaR[4] + \".F\" + rBNhIaR[7] + rBNhIaR[9] + rBNhIaR[12] + rBNhIaR[14];" fullword ascii
    $s3  = "yUdAL.open(yuLNp,LSopQ,false);" fullword ascii
    $s4  = "var rBNhIaR = \"Sc TQpGdXO r haAEzhlQV ipting vYIgBle BOF ile lanHBPVAuynZyw System sL inPxK Obj WgVgFC ect BLSEUiS ooZQw\".spli" ascii
    $s5  = "var daT = (\"2.XMLHTTP RlXTbDa TgbEO XML ream St LGDXociQ AD tqFRewS O BaJe D\").split(\" \");" fullword ascii
    $s6  = "var rBNhIaR = \"Sc TQpGdXO r haAEzhlQV ipting vYIgBle BOF ile lanHBPVAuynZyw System sL inPxK Obj WgVgFC ect BLSEUiS ooZQw\".spli" ascii
    $s7  = "if(q>=K.length) {break;}" fullword ascii
    $s8  = "return IHdwYbq(VN,SaWpO[481-475]+SaWpO[353-346]+SaWpO[710-702]);" fullword ascii
    $s9  = "function JIOBTeZ(YEVw) {" fullword ascii
    $s10 = "return EcYdD;" fullword ascii
    $s11 = "return YEVw.responseBody;" fullword ascii
    $s12 = "function iEyhfKQkg(LrktqqYRGhp) {" fullword ascii
    $s13 = "function MjQN(yUdAL,LSopQ,yuLNp) {" fullword ascii
    $s14 = "function vrVA(vRQTc) {" fullword ascii
    $s15 = "if (zoLTQ == 830-630){return true;} else {return false;}" fullword ascii
    $s16 = "function OErrf(sPKvho) {" fullword ascii
    $s17 = "function PGdoIcQLV() {" fullword ascii
    $s18 = "function zrDy(ISpmR,BhCpO) {" fullword ascii
    $s19 = "function NRWOXtlX(IVt) {" fullword ascii
    $s20 = "return new ActiveXObject(RUtRZM);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}