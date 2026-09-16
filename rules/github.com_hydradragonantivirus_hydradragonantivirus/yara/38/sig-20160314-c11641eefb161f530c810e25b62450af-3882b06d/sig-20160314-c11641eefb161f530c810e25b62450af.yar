rule sig_20160314_c11641eefb161f530c810e25b62450af {
  meta:
    description = "datamaliciousorder - file 20160314_c11641eefb161f530c810e25b62450af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0383b573a6a4471485fdd4855fde05f940cc95d7d6a9c7bdc85c719b09e23554"

  strings:
    $s1  = "var gr = true  , uzID = Yhq[7] + Yhq[9] + Yhq[11];" fullword ascii
    $s2  = "return hpwyvMZ[0] + hpwyvMZ[2] + hpwyvMZ[4] + \".F\" + hpwyvMZ[7] + hpwyvMZ[9] + hpwyvMZ[12] + hpwyvMZ[14];" fullword ascii
    $s3  = "var Yhq = (\"2.XMLHTTP VdXvDcO LmLwG XML ream St doSybbNw AD tNdNLSm O tAJD D\").split(\" \");" fullword ascii
    $s4  = "var hpwyvMZ = \"Sc sXdGBwq r kQkFuDclM ipting TDrCKqw qnp ile dcOloPxBBltOMt System Iv cPowc Obj BSWiPg ect iDEZgIV lgEbt\".spli" ascii
    $s5  = "var hpwyvMZ = \"Sc sXdGBwq r kQkFuDclM ipting TDrCKqw qnp ile dcOloPxBBltOMt System Iv cPowc Obj BSWiPg ect iDEZgIV lgEbt\".spli" ascii
    $s6  = "eKYIU.open(GQDIS,yhOOe,false);" fullword ascii
    $s7  = "function vfOOG(tjvygr) {" fullword ascii
    $s8  = "return kDWLt;" fullword ascii
    $s9  = "function iWtp(BOKZn) {" fullword ascii
    $s10 = "if (pyNRu == 1062-862){return true;} else {return false;}" fullword ascii
    $s11 = "return inY.size;" fullword ascii
    $s12 = "function RJoK(wZDnI,Vsfji) {" fullword ascii
    $s13 = "function GBrBe(tUSZbA) {" fullword ascii
    $s14 = "USe = N; break; " fullword ascii
    $s15 = "function QlrvtHnh() {" fullword ascii
    $s16 = "return bnHB.responseBody;" fullword ascii
    $s17 = "function nIbk(pzShp) {" fullword ascii
    $s18 = "return epMielt(Td,wkhVo[673-667]+wkhVo[799-792]+wkhVo[174-166]);" fullword ascii
    $s19 = "function QUwlcBVvc(XROxErkgQVF) {" fullword ascii
    $s20 = "function YbzI(DQLTf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}