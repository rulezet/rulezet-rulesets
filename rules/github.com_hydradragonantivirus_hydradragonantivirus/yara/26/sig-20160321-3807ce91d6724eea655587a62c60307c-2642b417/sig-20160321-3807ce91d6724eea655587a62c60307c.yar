rule sig_20160321_3807ce91d6724eea655587a62c60307c {
  meta:
    description = "datamaliciousorder - file 20160321_3807ce91d6724eea655587a62c60307c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e265d74ef007de2fc5dbadf588a55533098b62121cb7ef6d9e2f546f2a90859d"

  strings:
    $s1  = "return WScript.CreateObject(XgIoZ);" fullword ascii
    $s2  = "var Ja = true  , Buhs = HdJ[7] + HdJ[9] + HdJ[11];" fullword ascii
    $s3  = "return PtOEkrx[0] + PtOEkrx[2] + PtOEkrx[4] + \".F\" + PtOEkrx[7] + PtOEkrx[9] + PtOEkrx[12] + PtOEkrx[14];" fullword ascii
    $s4  = "JDYOg.open(irZln,kNBbg,false);" fullword ascii
    $s5  = "var PtOEkrx = yYJgR(RViXfpWELl+\" \"+\"System Qg DQFBJ Obj yYHpqF ect qmnlAbi EHSEj\", \" \");" fullword ascii
    $s6  = "var HdJ = (\"2.XMLHTTP lQWeaal HHXqs XML ream St jdysnSyM AD cFEZAnh O huVb D\").split(\" \");" fullword ascii
    $s7  = "function RhdceErPv(BSJIq) {" fullword ascii
    $s8  = "return dWK.size;" fullword ascii
    $s9  = "function Tovq(auCtX) {" fullword ascii
    $s10 = "function qasP(EyBsh) {" fullword ascii
    $s11 = "function eNFa(JDYOg,kNBbg,irZln) {" fullword ascii
    $s12 = "function wgEB(wfwxb) {" fullword ascii
    $s13 = "function IzYbA(lhYEse) {" fullword ascii
    $s14 = "function fkkvm(jhAuRL) {" fullword ascii
    $s15 = "return lhYEse.position=268-268;" fullword ascii
    $s16 = "function bcda(YQcpy,BdvCe) {" fullword ascii
    $s17 = "return hzjYB.status;" fullword ascii
    $s18 = "function MnLk(XgIoZ) {" fullword ascii
    $s19 = "function iSHr(JqTOe,oxhod) {" fullword ascii
    $s20 = "if (wfwxb == 795-595){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}