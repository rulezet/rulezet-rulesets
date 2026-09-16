rule sig_20160323_855eeb6f7b5a55a42ebba0b15a337cb3 {
  meta:
    description = "datamaliciousorder - file 20160323_855eeb6f7b5a55a42ebba0b15a337cb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35b16ed00c39b47dacb3c430e088e577264e2a4122b24a4ff852f3017119be5a"

  strings:
    $s1  = "return WScript.CreateObject(vmhHk);" fullword ascii
    $s2  = "return pzDgCnT[0] + pzDgCnT[2] + pzDgCnT[4] + \".F\" + pzDgCnT[7] + pzDgCnT[9] + pzDgCnT[12] + pzDgCnT[14];" fullword ascii
    $s3  = "function BJGy(TmPLT,NsyXf,XJFai) {" fullword ascii
    $s4  = "HOer.open(XJFai,NsyXf,false);" fullword ascii
    $s5  = "var pzDgCnT = hDDPS(XfzcgrMXgr+\" \"+\"System dk xIUXU Obj hsCIEG ect KBuHeuN OHOnn\", \" \");" fullword ascii
    $s6  = "if(F>=J.length) {break;}" fullword ascii
    $s7  = "function eAvL(ZFdla) {" fullword ascii
    $s8  = "function QRBv(OuEck,ykgwu) {" fullword ascii
    $s9  = "if (o >= spWlK.length) {break;}" fullword ascii
    $s10 = "return new ActiveXObject(JkDk);" fullword ascii
    $s11 = "function aivBZGh(MGPt,hLOBp) {" fullword ascii
    $s12 = "function TDzlzLsQO(dGrJD) {" fullword ascii
    $s13 = "function KTwyD(MjRgpO) {" fullword ascii
    $s14 = "function WIvD(spWlK) {" fullword ascii
    $s15 = "function SRSq(Glucd) {" fullword ascii
    $s16 = "function WEvF(vhkxt) {" fullword ascii
    $s17 = "function qKveWvyt(soH) {" fullword ascii
    $s18 = "if (JgMAq > 168270-362){return true;} else {return false;}" fullword ascii
    $s19 = "function XyqZ(qUCPE) {" fullword ascii
    $s20 = "return Zvgr[mQrxog[0]];" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}