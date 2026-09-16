rule sig_20160322_8f471e697cb1fa75c875e8149c9d116d {
  meta:
    description = "datamaliciousorder - file 20160322_8f471e697cb1fa75c875e8149c9d116d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfa8cd692724ec0823aaa5b032356d06ca4fe42b5dcb742171bee4234e2eb09a"

  strings:
    $s1  = "return WScript.CreateObject(qXlmZ);" fullword ascii
    $s2  = "var NA = true  , CuRC = IDR[7] + IDR[9] + IDR[11];" fullword ascii
    $s3  = "return wnKOnhw[0] + wnKOnhw[2] + wnKOnhw[4] + \".F\" + wnKOnhw[7] + wnKOnhw[9] + wnKOnhw[12] + wnKOnhw[14];" fullword ascii
    $s4  = "ApEQ.open(CpUEv,WQuis,false);" fullword ascii
    $s5  = "var wnKOnhw = rpjzv(EVxbmQKdQO+\" \"+\"System TW qVZpV Obj zdjqQU ect rotUKfj lvRvq\", \" \");" fullword ascii
    $s6  = "var IDR = (\"2.XMLHTTP cGbNrPG ItiXT XML ream St Fngriqjp AD yaPcmZV O JjHD D\").split(\" \");" fullword ascii
    $s7  = "function KUex(tNXkQ) {" fullword ascii
    $s8  = "return CWgkh;" fullword ascii
    $s9  = "function JxJmCbU(AkAZ) {" fullword ascii
    $s10 = "uYp = H; break; " fullword ascii
    $s11 = "function Cpqh(JWAjY,zPEZj) {" fullword ascii
    $s12 = "function ELlSJlCQn(ZaMnK) {" fullword ascii
    $s13 = "function AJXPH(CthYay) {" fullword ascii
    $s14 = "function BBIV(CMCji) {" fullword ascii
    $s15 = "return SYTwy.status;" fullword ascii
    $s16 = "function tUqH(CcbDZ) {" fullword ascii
    $s17 = "function mVqF(esIvW,WQuis,CpUEv) {" fullword ascii
    $s18 = "return QYL.size;" fullword ascii
    $s19 = "function gKBoU(vzJtqe) {" fullword ascii
    $s20 = "function PNsBpuCl(eAKx) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}