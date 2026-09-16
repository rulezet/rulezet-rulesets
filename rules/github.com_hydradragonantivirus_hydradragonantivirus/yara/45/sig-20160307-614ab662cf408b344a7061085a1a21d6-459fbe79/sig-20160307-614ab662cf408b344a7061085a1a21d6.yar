rule sig_20160307_614ab662cf408b344a7061085a1a21d6 {
  meta:
    description = "datamaliciousorder - file 20160307_614ab662cf408b344a7061085a1a21d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aac14be8925f25fb3c76775f37fed65d0109e2ab1b35dcdaf5ef869429272078"

  strings:
    $s1  = "var tX = true  , fuDw = hKA[7] + hKA[9] + hKA[11];" fullword ascii
    $s2  = "return ZdwPeto[0] + ZdwPeto[2] + ZdwPeto[4] + \".F\" + ZdwPeto[7] + ZdwPeto[9] + ZdwPeto[12] + ZdwPeto[14];" fullword ascii
    $s3  = "var ZdwPeto = \"Sc DJZbypl r rQbIPaNpU ipting UKWIHkE dKs ile fViGkieIgSMYZy System Nf cTisY Obj WWCuOp ect TQDvtTi\".split(\" " ascii
    $s4  = "var hKA = (\"2.XMLHTTP lBkdkft CdGoh XML ream St jmedoJvO AD BIXTBuu O Uvcc D\").split(\" \");" fullword ascii
    $s5  = "DDhCE.open(OkNhx,ngNXe,false);" fullword ascii
    $s6  = "return cMcnU;" fullword ascii
    $s7  = "function phag(DDhCE,ngNXe,OkNhx) {" fullword ascii
    $s8  = "function Bgvd(Cjlng) {" fullword ascii
    $s9  = "if(V>=B.length) {break;}" fullword ascii
    $s10 = "if (e >= qsfzg.length) {break;}" fullword ascii
    $s11 = "function BnosDqFUH(xsOwu,bkKZJ,MlfYk,PqEv) {" fullword ascii
    $s12 = "function LiKpWqSO() {" fullword ascii
    $s13 = "function hrLpg(XZNhmW) {" fullword ascii
    $s14 = "return jDqejEe" fullword ascii
    $s15 = "return FOi.size;" fullword ascii
    $s16 = "function EjyS(UHiSz) {" fullword ascii
    $s17 = "function uWrw(LduTI,SkhKz) {" fullword ascii
    $s18 = "function fRwE(KYPsz) {" fullword ascii
    $s19 = "if (((new Date())>0,7888700888)) {" fullword ascii
    $s20 = "function atxN(qsfzg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}