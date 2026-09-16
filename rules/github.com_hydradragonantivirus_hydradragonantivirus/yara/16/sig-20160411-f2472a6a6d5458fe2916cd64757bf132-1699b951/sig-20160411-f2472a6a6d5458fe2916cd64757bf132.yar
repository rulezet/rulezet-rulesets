rule sig_20160411_f2472a6a6d5458fe2916cd64757bf132 {
  meta:
    description = "datamaliciousorder - file 20160411_f2472a6a6d5458fe2916cd64757bf132.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f79a8e19a6882335fcd44f1e118471119e17914f18763187c1136e3fd7c8e0b3"

  strings:
    $s1  = "Hfrc.open(ROFHc,yeRun,false);" fullword ascii
    $s2  = "return AWOTxaX[0] + AWOTxaX[2] + AWOTxaX[4] + \".F\" + AWOTxaX[7] + AWOTxaX[9] + AWOTxaX[12] + AWOTxaX[14];" fullword ascii
    $s3  = "var pg = true  , OFVD = tnH[7] + tnH[9] + tnH[11];" fullword ascii
    $s4  = "var tnH = (\"2.XMLHTTP IxkSRTd XXsxp XML ream St HoVutWhe AD pYgipKS O suGq D\").split(\" \");" fullword ascii
    $s5  = "function NJsD(faqKa,yeRun,ROFHc) {" fullword ascii
    $s6  = "if(D>=G.length) {break;}" fullword ascii
    $s7  = "return WrECMm[pvDZ[707-707]]=643-643;" fullword ascii
    $s8  = "function PEcQCJMkh(VwnIcMhjHRd) {" fullword ascii
    $s9  = "function tQpty(oUqBjAyR,ljhY) {" fullword ascii
    $s10 = "return aJx.size;" fullword ascii
    $s11 = "function vGEd(kMeiW) {" fullword ascii
    $s12 = "function ELfB(wvzjN) {" fullword ascii
    $s13 = "function QTjgv(wpQUtA) {" fullword ascii
    $s14 = "function BCmK(VgyML) {" fullword ascii
    $s15 = "return Jbasb.status;" fullword ascii
    $s16 = "return DLqbWkv[0];" fullword ascii
    $s17 = "function usPGMXdHh(kbhbm) {" fullword ascii
    $s18 = "return new ActiveXObject(FsKh);" fullword ascii
    $s19 = "function XMIa(nsePD,jlKbC) {" fullword ascii
    $s20 = "function mzDK(wRhZy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}