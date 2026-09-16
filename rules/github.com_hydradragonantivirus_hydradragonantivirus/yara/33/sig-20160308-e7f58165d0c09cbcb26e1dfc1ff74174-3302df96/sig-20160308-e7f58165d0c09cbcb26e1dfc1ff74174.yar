rule sig_20160308_e7f58165d0c09cbcb26e1dfc1ff74174 {
  meta:
    description = "datamaliciousorder - file 20160308_e7f58165d0c09cbcb26e1dfc1ff74174.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3d0b4f4decc0b1c120e60513fd47c194da6fee77fda7834d937c027f1335d41"

  strings:
    $s1  = "return DNgVsPl[0] + DNgVsPl[2] + DNgVsPl[4] + \".F\" + DNgVsPl[7] + DNgVsPl[9] + DNgVsPl[12] + DNgVsPl[14];" fullword ascii
    $s2  = "var Ae = true  , ussz = IaA[7] + IaA[9] + IaA[11];" fullword ascii
    $s3  = "var DNgVsPl = \"Sc loRTtkE r LvKxEcxvT ipting tEefsCT AqA ile jEkVzauYzeTyrD System AR SQjbT Obj aPNQGt ect WlLRQMv\".split(\" " ascii
    $s4  = "var IaA = (\"2.XMLHTTP gROMZfU yphmZ XML ream St eQIiWutS AD fKdMUHi O MMUr D\").split(\" \");" fullword ascii
    $s5  = "rHpLD.open(eumvc,kENel,false);" fullword ascii
    $s6  = "zqk = y; break; " fullword ascii
    $s7  = "function LGdH(zOuRS) {" fullword ascii
    $s8  = "function swXpRlBkZ(SMvJNkrSbgY) {" fullword ascii
    $s9  = "return MO.ExpandEnvironmentStrings(KENGL[6]+KENGL[7]+KENGL[8]);" fullword ascii
    $s10 = "return VZIlo.status;" fullword ascii
    $s11 = "function SkMjXXFwP(bmEdY,XuhDa,JUpsY,wwyr) {" fullword ascii
    $s12 = "return ysJR.responseBody;" fullword ascii
    $s13 = "if (zOuRS > 197853-559){return true;} else {return false;}" fullword ascii
    $s14 = "function Zakc(gUjvw) {" fullword ascii
    $s15 = "function NPeu(wtbjm,vKYxT) {" fullword ascii
    $s16 = "return QWLYfjG" fullword ascii
    $s17 = "return new ActiveXObject(vXCwui);" fullword ascii
    $s18 = "return OxW.size;" fullword ascii
    $s19 = "function SxBHY(vXCwui) {" fullword ascii
    $s20 = "function gOSM(rHpLD,kENel,eumvc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}