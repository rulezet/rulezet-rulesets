rule sig_20160324_75870b114db9bb5d4f0ce24855daef99 {
  meta:
    description = "datamaliciousorder - file 20160324_75870b114db9bb5d4f0ce24855daef99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adbd6bfbf78f6f263df2202d88b69ed153654b1736a65c0b060db2c98f4247e6"

  strings:
    $s1  = "return WScript.CreateObject(otnYO);" fullword ascii
    $s2  = "return InmVael[0] + InmVael[2] + InmVael[4] + \".F\" + InmVael[7] + InmVael[9] + InmVael[12] + InmVael[14];" fullword ascii
    $s3  = "var vN = true  , Pjdm = Idt[7] + Idt[9] + Idt[11];" fullword ascii
    $s4  = "var Idt = (\"2.XMLHTTP VTGQnmL vtxKC XML ream St mgBWHMzD AD AqRvaHS O dIwN D\").split(\" \");" fullword ascii
    $s5  = "var InmVael = ujMHE(SDTqAmQfNO+\" \"+\"System rs xFEEr Obj DZcnMQ ect VmfAuGm UEHqB\", \" \");" fullword ascii
    $s6  = "WjWT.open(mdbqp,KapoW,false);" fullword ascii
    $s7  = "function tvFQd(ZKuJMdoG,ugEd) {" fullword ascii
    $s8  = "if (h >= HsZoW.length) {break;}" fullword ascii
    $s9  = "if(b>=p.length) {break;}" fullword ascii
    $s10 = "return DHOZN;" fullword ascii
    $s11 = "function LammPZOOF(xjmOY) {" fullword ascii
    $s12 = "function TwaqGmF(fVHj) {" fullword ascii
    $s13 = "return tNP.split(AuJMa);" fullword ascii
    $s14 = "function QVvn(bjbYX,zdoKn) {" fullword ascii
    $s15 = "var lPACLAn = \"odOWLX*YDI*pt.S\"+\"hell*HPkuVAC*Scri*\";" fullword ascii
    $s16 = "return xMAbs.status;" fullword ascii
    $s17 = "function LasbxZicj(IuQNESePIdr) {" fullword ascii
    $s18 = "function NJaR(xnzqm,KapoW,mdbqp) {" fullword ascii
    $s19 = "return qWkV.ExpandEnvironmentStrings(iRdnL);" fullword ascii
    $s20 = "if (vfrpi == 538-338){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}