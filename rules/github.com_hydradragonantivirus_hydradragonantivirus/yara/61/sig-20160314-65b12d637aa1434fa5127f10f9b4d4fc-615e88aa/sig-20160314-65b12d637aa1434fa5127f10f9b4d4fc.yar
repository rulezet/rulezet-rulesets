rule sig_20160314_65b12d637aa1434fa5127f10f9b4d4fc {
  meta:
    description = "datamaliciousorder - file 20160314_65b12d637aa1434fa5127f10f9b4d4fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c8fbf36226747dcaa2ee3933a95913daca2dca2cb9ccf7039a183e43b9f4279"

  strings:
    $s1  = "var uq = true  , PxpU = osh[7] + osh[9] + osh[11];" fullword ascii
    $s2  = "return zDOhZqR[0] + zDOhZqR[2] + zDOhZqR[4] + \".F\" + zDOhZqR[7] + zDOhZqR[9] + zDOhZqR[12] + zDOhZqR[14];" fullword ascii
    $s3  = "var zDOhZqR = \"Sc MpcfWxw r GYODSHSlt ipting WnYljMk IJl ile TrwatKSiaExxVQ System QN zQgmp Obj gHtKGp ect jXxFvWI DtIil\".spli" ascii
    $s4  = "uYfAf.open(FRSjl,LdDvC,false);" fullword ascii
    $s5  = "var zDOhZqR = \"Sc MpcfWxw r GYODSHSlt ipting WnYljMk IJl ile TrwatKSiaExxVQ System QN zQgmp Obj gHtKGp ect jXxFvWI DtIil\".spli" ascii
    $s6  = "var osh = (\"2.XMLHTTP GqhWxFG DUIOG XML ream St KnNyhitk AD GijMqRb O ksIu D\").split(\" \");" fullword ascii
    $s7  = "if(o>=O.length) {break;}" fullword ascii
    $s8  = "if (JZARp == 1184-984){return true;} else {return false;}" fullword ascii
    $s9  = "if (jeBZl > 164836-862){return true;} else {return false;}" fullword ascii
    $s10 = "function tKUGw(KeTtxH) {" fullword ascii
    $s11 = "return XxbvDTe(Rx,FCEbt[136-130]+FCEbt[479-472]+FCEbt[444-436]);" fullword ascii
    $s12 = "ftu = o; break; " fullword ascii
    $s13 = "function ePLm(UinYn) {" fullword ascii
    $s14 = "return VfjA.ExpandEnvironmentStrings(CxOpr);" fullword ascii
    $s15 = "return lRpqpKL" fullword ascii
    $s16 = "function ROLI(EVpNA) {" fullword ascii
    $s17 = "function ZruA(MycoO) {" fullword ascii
    $s18 = "return ENbBI;" fullword ascii
    $s19 = "return uZk.size;" fullword ascii
    $s20 = "function XxbvDTe(VfjA,CxOpr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}