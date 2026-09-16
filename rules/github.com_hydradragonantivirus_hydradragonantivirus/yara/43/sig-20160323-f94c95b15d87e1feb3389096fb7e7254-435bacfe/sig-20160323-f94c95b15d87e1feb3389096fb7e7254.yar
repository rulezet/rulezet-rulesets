rule sig_20160323_f94c95b15d87e1feb3389096fb7e7254 {
  meta:
    description = "datamaliciousorder - file 20160323_f94c95b15d87e1feb3389096fb7e7254.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1794ff0dc3406c14c6416691f1efb247ccdddd9fb999478f62148507bf9fecd"

  strings:
    $s1  = "return WScript.CreateObject(sQnGN);" fullword ascii
    $s2  = "var JA = true  , RjnJ = fth[7] + fth[9] + fth[11];" fullword ascii
    $s3  = "return ABxzqxl[0] + ABxzqxl[2] + ABxzqxl[4] + \".F\" + ABxzqxl[7] + ABxzqxl[9] + ABxzqxl[12] + ABxzqxl[14];" fullword ascii
    $s4  = "var ABxzqxl = HRpHd(LtcwvCUlQL+\" \"+\"System iV DTLND Obj yOqnEB ect tPqRZrR pEpeF\", \" \");" fullword ascii
    $s5  = "function ADSkEFig(wbIN) {" fullword ascii
    $s6  = "if (X >= rjsmm.length) {break;}" fullword ascii
    $s7  = "function OLkt(PAtOl) {" fullword ascii
    $s8  = "return RCe.size;" fullword ascii
    $s9  = "return piZki;" fullword ascii
    $s10 = "if (PAtOl == 623-423){return true;} else {return false;}" fullword ascii
    $s11 = "function PkuX(sQnGN) {" fullword ascii
    $s12 = "function uUch(dEhRP,WRCye) {" fullword ascii
    $s13 = "function zuhMs(cGzJpG) {" fullword ascii
    $s14 = "return ToPopJy(hy,HWoOy[299-293]+HWoOy[904-897]+HWoOy[612-604]);" fullword ascii
    $s15 = "return fBP.split(xhBhk);" fullword ascii
    $s16 = "return cGzJpG/*2mLcLWOklxZ2YATaK7VyMC8D3*/.position=320-320;" fullword ascii
    $s17 = "return PcXfn.status;" fullword ascii
    $s18 = "function HjogD(JGMzHh) {" fullword ascii
    $s19 = "function VOvv(FnODg) {" fullword ascii
    $s20 = "function qOwm(xFdtG) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}