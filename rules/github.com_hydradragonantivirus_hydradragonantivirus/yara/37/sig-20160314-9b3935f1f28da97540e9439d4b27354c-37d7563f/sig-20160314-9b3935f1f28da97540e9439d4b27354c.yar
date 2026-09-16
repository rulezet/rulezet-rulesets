rule sig_20160314_9b3935f1f28da97540e9439d4b27354c {
  meta:
    description = "datamaliciousorder - file 20160314_9b3935f1f28da97540e9439d4b27354c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43469d0595ece605a6efe419749101e3f1b4f2717ea012b859628a64385dc68b"

  strings:
    $s1  = "var fj = true  , fCip = fmP[7] + fmP[9] + fmP[11];" fullword ascii
    $s2  = "return byBtZzc[0] + byBtZzc[2] + byBtZzc[4] + \".F\" + byBtZzc[7] + byBtZzc[9] + byBtZzc[12] + byBtZzc[14];" fullword ascii
    $s3  = "var fmP = (\"2.XMLHTTP mTZOUQP GpNJh XML ream St eRNfZgss AD SRkgUFh O noRE D\").split(\" \");" fullword ascii
    $s4  = "MmuGc.open(UpOmT,gywPL,false);" fullword ascii
    $s5  = "var byBtZzc = \"Sc idmFCIN r mXvOjCXdN ipting huuJPny FgW ile kfzYrptpxGlIvU System cj kHbup Obj vsXDaU ect WEKrcJj Xhyit\".spli" ascii
    $s6  = "var byBtZzc = \"Sc idmFCIN r mXvOjCXdN ipting huuJPny FgW ile kfzYrptpxGlIvU System cj kHbup Obj vsXDaU ect WEKrcJj Xhyit\".spli" ascii
    $s7  = "if (hvarG > 157079-984){return true;} else {return false;}" fullword ascii
    $s8  = "function zQJKSfNp(NkT) {" fullword ascii
    $s9  = "function IKxTpdey() {" fullword ascii
    $s10 = "function xvsa(hvarG) {" fullword ascii
    $s11 = "return DYhbZns(Rj,UKtnP[546-540]+UKtnP[499-492]+UKtnP[395-387]);" fullword ascii
    $s12 = "function Pzuc(HLVJc) {" fullword ascii
    $s13 = "if (o >= wHoNo.length) {break;}" fullword ascii
    $s14 = "return NkT.size;" fullword ascii
    $s15 = "return giTsl.status;" fullword ascii
    $s16 = "function lgcsDKN(FCmg) {" fullword ascii
    $s17 = "function jXuB(beCVA,yfYLL) {" fullword ascii
    $s18 = "function DYhbZns(OJNR,mdpmF) {" fullword ascii
    $s19 = "return new ActiveXObject(iJacke);" fullword ascii
    $s20 = "return rWYYNu.position=945-945;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}