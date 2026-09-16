rule sig_20160411_5de16b7c0baf3c2128bed012ce2e4b0d {
  meta:
    description = "datamaliciousorder - file 20160411_5de16b7c0baf3c2128bed012ce2e4b0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7a5e2e38dfdb877e90160d955c0b33077c536387e17a71e37480a20b998796a"

  strings:
    $s1  = "function nHackqxQ(spYD) {" fullword ascii
    $s2  = "return yuDzfGf[0] + yuDzfGf[2] + yuDzfGf[4] + \".F\" + yuDzfGf[7] + yuDzfGf[9] + yuDzfGf[12] + yuDzfGf[14];" fullword ascii
    $s3  = "var em = true  , WgIt = ZpQ[7] + ZpQ[9] + ZpQ[11];" fullword ascii
    $s4  = "MGtv.open(HIrSi,vxNIv,false);" fullword ascii
    $s5  = "function EKWDcMdT(Eio) {" fullword ascii
    $s6  = "var ZpQ = (\"2.XMLHTTP OqcHyEH UnvjH XML ream St XAyPldOB AD hOPcMRO O JmNc D\").split(\" \");" fullword ascii
    $s7  = "function dhvtI(xkWvtp) {" fullword ascii
    $s8  = "return VHc[AVeJ[0]](IVbkg);" fullword ascii
    $s9  = "return eJBpV;" fullword ascii
    $s10 = "function uHSC(dKeaO,YSola) {" fullword ascii
    $s11 = "function fCLa(gmPOw) {" fullword ascii
    $s12 = "if (qGQkx == 327-127){return true;} else {return false;}" fullword ascii
    $s13 = "function ObByx(jkCBly) {" fullword ascii
    $s14 = "return \"SGQcVaPkrpHzfd\";" fullword ascii
    $s15 = "function EdkxeGD(cunM,phYpv) {" fullword ascii
    $s16 = "return EdkxeGD(Ry,aODGLC+fuWJe[604-596]);" fullword ascii
    $s17 = "function ElGOOqDxZ(qsXTbyRKxfo) {" fullword ascii
    $s18 = "function gCzI(UXaas,vxNIv,HIrSi) {" fullword ascii
    $s19 = "return new ActiveXObject(PmrC);" fullword ascii
    $s20 = "if (h >= iXXKl.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}