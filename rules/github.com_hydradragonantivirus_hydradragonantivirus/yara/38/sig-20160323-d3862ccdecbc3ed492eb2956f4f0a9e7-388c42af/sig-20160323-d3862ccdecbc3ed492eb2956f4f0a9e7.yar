rule sig_20160323_d3862ccdecbc3ed492eb2956f4f0a9e7 {
  meta:
    description = "datamaliciousorder - file 20160323_d3862ccdecbc3ed492eb2956f4f0a9e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9c59788a5b1b26d12d7d6d33b5d1349dcc700d2c3c686f904c3afa31ec87662"

  strings:
    $s1  = "return WScript.CreateObject(Mtoad);" fullword ascii
    $s2  = "var NB = true  , dMbt = bKB[7] + bKB[9] + bKB[11];" fullword ascii
    $s3  = "return mVngrfF[0] + mVngrfF[2] + mVngrfF[4] + \".F\" + mVngrfF[7] + mVngrfF[9] + mVngrfF[12] + mVngrfF[14];" fullword ascii
    $s4  = "FDQI.open(dueGd,sjetK,false);" fullword ascii
    $s5  = "var bKB = (\"2.XMLHTTP WvkIUWE PMtiY XML ream St EtDlcstg AD ljbvRoO O fcYZ D\").split(\" \");" fullword ascii
    $s6  = "var mVngrfF = TIIrJ(dfgUSNCDjw+\" \"+\"System JN jZFZu Obj slhWlT ect wyZBSPt EsHpj\", \" \");" fullword ascii
    $s7  = "if (dvwxX > 167254-984){return true;} else {return false;}" fullword ascii
    $s8  = "function zzhk(Mtoad) {" fullword ascii
    $s9  = "function sBpMZUQJ(Vba) {" fullword ascii
    $s10 = "function crMe(QuTXf) {" fullword ascii
    $s11 = "if (NINGv == 333-133){return true;} else {return false;}" fullword ascii
    $s12 = "return ezCL.ExpandEnvironmentStrings(riYkE);" fullword ascii
    $s13 = "return xWjexx/*57hBwiS3SANk1TJnBOOsEbSeH*/.position=144-144;" fullword ascii
    $s14 = "return new ActiveXObject(wGOB);" fullword ascii
    $s15 = "function iPqyiqNxT(dRzNr) {" fullword ascii
    $s16 = "return RbiRoko(La,MoUal[858-852]+MoUal[285-278]+MoUal[267-259]);" fullword ascii
    $s17 = "function ueFI(NINGv) {" fullword ascii
    $s18 = "function lmdBrQt(XmJi) {" fullword ascii
    $s19 = "function bLVDK(xWjexx) {" fullword ascii
    $s20 = "function feGW(MVxOp,TzOvE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}