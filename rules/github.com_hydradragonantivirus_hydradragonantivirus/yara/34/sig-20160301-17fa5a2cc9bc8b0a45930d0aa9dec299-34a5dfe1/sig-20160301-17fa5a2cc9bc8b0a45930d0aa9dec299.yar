rule sig_20160301_17fa5a2cc9bc8b0a45930d0aa9dec299 {
  meta:
    description = "datamaliciousorder - file 20160301_17fa5a2cc9bc8b0a45930d0aa9dec299.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06a5baa449200e368c03a0c5f6c55192b663940b8f8070de1fe21af330cb75c5"

  strings:
    $s1  = "var bJ = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(YnuCk);" fullword ascii
    $s3  = "return \"Sc\" + \"r\" + ktLZUHP + \".F\" + yDQlAxQWgS + tsBdq + \"Obj\" + \"ect\";" fullword ascii
    $s4  = "var YZ = true  , aiEK = fpO[7] + \"\" + fpO[9];" fullword ascii
    $s5  = "var fpO = (XdP + \"TTP\" + \" qIvHCRf WThqy XML ream St IAeDvMvm AD lvwdboN OD\").split(\" \");" fullword ascii
    $s6  = "CMrxE.open(dhlWY,rcxad,false);" fullword ascii
    $s7  = "function Mrqp(pSjNq,xQfDi) {" fullword ascii
    $s8  = "function weQl(SVORN) {" fullword ascii
    $s9  = "function OWRIr(bKtXWS) {" fullword ascii
    $s10 = "if (SBzWw == 719-519){return true;} else {return false;}" fullword ascii
    $s11 = "if(U>=x.length) {break;}" fullword ascii
    $s12 = "return IzUok;" fullword ascii
    $s13 = "function LvwP(SBzWw) {" fullword ascii
    $s14 = "function KVWX(YnuCk) {" fullword ascii
    $s15 = "if (((new Date())>0,7439980888)) {" fullword ascii
    $s16 = "if (SVORN > 164714-687){return true;} else {return false;}" fullword ascii
    $s17 = "function VPxg(pjEWM) {" fullword ascii
    $s18 = "return new ActiveXObject(bKtXWS);" fullword ascii
    $s19 = "function PethkLmBu(oFiZf,uOSDb,hXPGQ) {" fullword ascii
    $s20 = "function XznkfsTv() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}