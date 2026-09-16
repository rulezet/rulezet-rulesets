rule sig_20160405_af7804cb79de852072d2e10386638296 {
  meta:
    description = "datamaliciousorder - file 20160405_af7804cb79de852072d2e10386638296.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740da67a9a475dca3923b147be3e524dc022d85e9b2986b18d93623b0067e633"

  strings:
    $s1  = "return TVZrmVS[0] + TVZrmVS[2] + TVZrmVS[4] + \".F\" + TVZrmVS[7] + TVZrmVS[9] + TVZrmVS[12] + TVZrmVS[14];" fullword ascii
    $s2  = "var sT = true  , uGSV = fUs[7] + fUs[9] + fUs[11];" fullword ascii
    $s3  = "THgK.open(yozHr,YUtEj,false);" fullword ascii
    $s4  = "var fUs = (\"2.XMLHTTP UwrcoZH RPhBk XML ream St hnRFwFNQ AD TRFWDux O pvtp D\").split(\" \");" fullword ascii
    $s5  = "if(S>=E.length) {break;}" fullword ascii
    $s6  = "function juYU(Ocvrm) {" fullword ascii
    $s7  = "function tIROrOX(MBQm,buUuN) {" fullword ascii
    $s8  = "return KCmo[KIulyA[0]];" fullword ascii
    $s9  = "return XSP.size;" fullword ascii
    $s10 = "function WFNuIM(pHPjBuo) {" fullword ascii
    $s11 = "function drRe(FhiYa) {" fullword ascii
    $s12 = "return \"gIMtGsAxAPvfdz\";" fullword ascii
    $s13 = "if (FhiYa > 195127-472){return true;} else {return false;}" fullword ascii
    $s14 = "function nrBw(NDBQH,XwRtq) {" fullword ascii
    $s15 = "function APGP(ADxar,YUtEj,yozHr) {" fullword ascii
    $s16 = "return KZPYn.status;" fullword ascii
    $s17 = "function IvyhV(bEc,fAGKJ) {" fullword ascii
    $s18 = "return kNrCDFy[0];" fullword ascii
    $s19 = "function rpQVJG(vkIG,LMFwQq) {" fullword ascii
    $s20 = "return tIROrOX(HG,zCRJt[945-939]+zCRJt[919-912]+zCRJt[362-354]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}