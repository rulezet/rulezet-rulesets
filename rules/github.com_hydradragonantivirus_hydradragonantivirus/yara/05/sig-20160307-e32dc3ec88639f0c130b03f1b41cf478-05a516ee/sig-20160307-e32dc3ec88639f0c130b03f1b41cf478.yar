rule sig_20160307_e32dc3ec88639f0c130b03f1b41cf478 {
  meta:
    description = "datamaliciousorder - file 20160307_e32dc3ec88639f0c130b03f1b41cf478.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0651de230c0879bebbbd912bc595c7a92159ea68f6d809c28bb6bf766d747f7"

  strings:
    $s1  = "return QdmDPDU[0] + QdmDPDU[2] + QdmDPDU[4] + \".F\" + QdmDPDU[7] + QdmDPDU[9] + QdmDPDU[12] + QdmDPDU[14];" fullword ascii
    $s2  = "var fp = true  , iKTY = Pvi[7] + Pvi[9] + Pvi[11];" fullword ascii
    $s3  = "var QdmDPDU = \"Sc elkaztR r pqSMbxCcM ipting MebQhTX teN ile tVIgUdJhxWylrK System uU uaSFX Obj yRDlcN ect ZcOHUiq\".split(\" " ascii
    $s4  = "clqlF.open(XsZPX,xqJwd,false);" fullword ascii
    $s5  = "var Pvi = (\"2.XMLHTTP kuCobXT RPHQo XML ream St VlAsbBEi AD qldgDeJ O FEAq D\").split(\" \");" fullword ascii
    $s6  = "function CKXx(QyDQZ) {" fullword ascii
    $s7  = "ghC = A; break; " fullword ascii
    $s8  = "function rtoj(ZyLtc) {" fullword ascii
    $s9  = "function icES(Bslnr) {" fullword ascii
    $s10 = "function OuzQuGGh() {" fullword ascii
    $s11 = "if (tgyZd == 941-741){return true;} else {return false;}" fullword ascii
    $s12 = "return VqVLf;" fullword ascii
    $s13 = "if (vusrr > 166859-709){return true;} else {return false;}" fullword ascii
    $s14 = "return tcsiq.status;" fullword ascii
    $s15 = "function qmlt(UMyAh,kmaTF) {" fullword ascii
    $s16 = "function tabs(qYPYB) {" fullword ascii
    $s17 = "return wlW.size;" fullword ascii
    $s18 = "if (((new Date())>0,7796004888)) {" fullword ascii
    $s19 = "function rElO(tcsiq) {" fullword ascii
    $s20 = "function nZhpz(SCEwVh) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}