rule sig_20160313_c6670956c4c930c31ebfdb1b72ab8e21 {
  meta:
    description = "datamaliciousorder - file 20160313_c6670956c4c930c31ebfdb1b72ab8e21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4d7733fa92e2e7f1668d6d089805987567d6ddd38afef18afc9e759d52105d9"

  strings:
    $s1  = "var lTkiA = \"OuRFZk;KDJ;pt.Shell;jRNUDyf;Scri;pAWL;%TE;MP%;\\\\;UtAjUlvcN;ONNeRJ;IqyFiHe\".split(\";\");" fullword ascii
    $s2  = "return smnorEJ[0] + smnorEJ[2] + smnorEJ[4] + \".F\" + smnorEJ[7] + smnorEJ[9] + smnorEJ[12] + smnorEJ[14];" fullword ascii
    $s3  = "var fI = true  , KIzH = LiZ[7] + LiZ[9] + LiZ[11];" fullword ascii
    $s4  = "var smnorEJ = \"Sc TDVitcq r FYisnjHyu ipting WlFqzQn hZk ile igUGctHjXaLDSs System wS TKVTO Obj GfWkIJ ect JhJAtvi\".split(\" " ascii
    $s5  = "xqADc.open(JDlAJ,oVKan,false);" fullword ascii
    $s6  = "if(D>=s.length) {break;}" fullword ascii
    $s7  = "function swjp(zMDVG) {" fullword ascii
    $s8  = "function YDoeasg(mlhR,NsXnH) {" fullword ascii
    $s9  = "function ESBtaDSH() {" fullword ascii
    $s10 = "return eDmLScm" fullword ascii
    $s11 = "function aBGq(Gbbyg) {" fullword ascii
    $s12 = "function bmAcD(zuedyc) {" fullword ascii
    $s13 = "if (byOmI > 195587-795){return true;} else {return false;}" fullword ascii
    $s14 = "return WyeFj.status;" fullword ascii
    $s15 = "CKd = D; break; " fullword ascii
    $s16 = "return YDoeasg(Fm,lTkiA[662-656]+lTkiA[310-303]+lTkiA[444-436]);" fullword ascii
    $s17 = "function fMJfjhG(RuCR) {" fullword ascii
    $s18 = "return new ActiveXObject(zuedyc);" fullword ascii
    $s19 = "return evKOgT.position=524-524;" fullword ascii
    $s20 = "return ceviO;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}