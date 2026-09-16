rule sig_20160405_028871a3ed8357bff997c1c2a13dc159 {
  meta:
    description = "datamaliciousorder - file 20160405_028871a3ed8357bff997c1c2a13dc159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3c3621a4584b71c468dc0d74c65a66eb2b6ab6c100a448f3e3e7deb0dde1c9c"

  strings:
    $s1  = "var uE = true  , ZkRg = VtJ[7] + VtJ[9] + VtJ[11];" fullword ascii
    $s2  = "return yOpDaqV[0] + yOpDaqV[2] + yOpDaqV[4] + \".F\" + yOpDaqV[7] + yOpDaqV[9] + yOpDaqV[12] + yOpDaqV[14];" fullword ascii
    $s3  = "var VtJ = (\"2.XMLHTTP cLdpVDF CRTHO XML ream St GWTNINlD AD UtwIpxi O XgUx D\").split(\" \");" fullword ascii
    $s4  = "ubnF.open(cDDlC,RSDPB,false);" fullword ascii
    $s5  = "if(W>=Y.length) {break;}" fullword ascii
    $s6  = "return lOAbx;" fullword ascii
    $s7  = "return oRwHm.status;" fullword ascii
    $s8  = "return \"RgdezsxRcRfWgv\";" fullword ascii
    $s9  = "function gzXaH(ovK,OiCfA) {" fullword ascii
    $s10 = "function yzXvYtFXl(XqnxiKMtIcZ) {" fullword ascii
    $s11 = "function UzBFjgdV(YMi) {" fullword ascii
    $s12 = "if (DrLEo > 154571-648){return true;} else {return false;}" fullword ascii
    $s13 = "function QXwkvIDo(jYDO) {" fullword ascii
    $s14 = "return new ActiveXObject(eqaV);" fullword ascii
    $s15 = "return ExEv[AakNTk[0]];" fullword ascii
    $s16 = "function qHKXjtd(ExEv) {" fullword ascii
    $s17 = "function eCsG(oRwHm) {" fullword ascii
    $s18 = "function fNQjqRb(wkId,TgFdI) {" fullword ascii
    $s19 = "return qlVbiKC[0];" fullword ascii
    $s20 = "ccN = W; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}