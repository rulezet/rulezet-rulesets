rule sig_20160315_a40255b488e3a95adeffe3f78c2bf782 {
  meta:
    description = "datamaliciousorder - file 20160315_a40255b488e3a95adeffe3f78c2bf782.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4369926ea9a5ee012eb940a9ff311c239270130e5e085acad9e0fe10fb4e9f90"

  strings:
    $s1  = "return tmMnfIq[0] + tmMnfIq[2] + tmMnfIq[4] + \".F\" + tmMnfIq[7] + tmMnfIq[9] + tmMnfIq[12] + tmMnfIq[14];" fullword ascii
    $s2  = "var TR = true  , Zjds = IfK[7] + IfK[9] + IfK[11];" fullword ascii
    $s3  = "MMwjr.open(SOYOG,TmzfC,false);" fullword ascii
    $s4  = "var IfK = (\"2.XMLHTTP QCXdWPm rvIvb XML ream St FVBTInEJ AD ElKtBCM O fAdR D\").split(\" \");" fullword ascii
    $s5  = "var tmMnfIq = lwWfQ(\"Sc fBazUbD r IwQzSspOo ipting ZnsuOyy Saz ile oVzcIWqMWKJIgq System Ww UYJZC Obj NlzeHb ect SlLKhNd ZzBgt" ascii
    $s6  = "ckt.CreateFolder(aSEm);" fullword ascii
    $s7  = "var tmMnfIq = lwWfQ(\"Sc fBazUbD r IwQzSspOo ipting ZnsuOyy Saz ile oVzcIWqMWKJIgq System Ww UYJZC Obj NlzeHb ect SlLKhNd ZzBgt" ascii
    $s8  = "if(F>=c.length) {break;}" fullword ascii
    $s9  = "function ykDi(MMwjr,TmzfC,SOYOG) {" fullword ascii
    $s10 = "function oCkK(NxMqk) {" fullword ascii
    $s11 = "return omuOD;" fullword ascii
    $s12 = "function lwWfQ(ypC,UpsoO) {" fullword ascii
    $s13 = "function mvgS(FBacj) {" fullword ascii
    $s14 = "if (z >= PwxuG.length) {break;}" fullword ascii
    $s15 = "var aSEm = pBP+gspnqP[0]+gspnqP[1];" fullword ascii
    $s16 = "function VvJPLnMB() {" fullword ascii
    $s17 = "return fsFsFOH(sZ,loaRS[136-130]+loaRS[268-261]+loaRS[624-616]);" fullword ascii
    $s18 = "function bqCN(uvZyA) {" fullword ascii
    $s19 = "HjI = F; break; " fullword ascii
    $s20 = "function iXCsUxIa(Uhg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}