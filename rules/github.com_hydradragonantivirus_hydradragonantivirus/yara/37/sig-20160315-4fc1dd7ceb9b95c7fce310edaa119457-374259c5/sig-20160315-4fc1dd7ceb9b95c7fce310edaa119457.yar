rule sig_20160315_4fc1dd7ceb9b95c7fce310edaa119457 {
  meta:
    description = "datamaliciousorder - file 20160315_4fc1dd7ceb9b95c7fce310edaa119457.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "490ba76e34e0b7ade6794dd653eaa48ddc231f3ad0f7115b98c2d33df227bb1d"

  strings:
    $s1  = "var oI = true  , IcPT = EBy[7] + EBy[9] + EBy[11];" fullword ascii
    $s2  = "return ZSpeyfX[0] + ZSpeyfX[2] + ZSpeyfX[4] + \".F\" + ZSpeyfX[7] + ZSpeyfX[9] + ZSpeyfX[12] + ZSpeyfX[14];" fullword ascii
    $s3  = "var ZSpeyfX = COXSS(\"Sc hrCZHyT r bbvshKszb ipting vfqJyxb DRV ile kihWMZdYGcfhll System pc IdhGP Obj BLuhzH ect aGwVLtD choON" ascii
    $s4  = "var ZSpeyfX = COXSS(\"Sc hrCZHyT r bbvshKszb ipting vfqJyxb DRV ile kihWMZdYGcfhll System pc IdhGP Obj BLuhzH ect aGwVLtD choON" ascii
    $s5  = "var EBy = (\"2.XMLHTTP YNDOqHc Jvhpo XML ream St rKLsHPON AD hgMSzEF O bJkV D\").split(\" \");" fullword ascii
    $s6  = "function YhuWojL(OLQF,QGQei) {" fullword ascii
    $s7  = "return OLQF.ExpandEnvironmentStrings(QGQei);" fullword ascii
    $s8  = "function ZhFxJYkz() {" fullword ascii
    $s9  = "if (rLZCO > 150749-487){return true;} else {return false;}" fullword ascii
    $s10 = "if (nuMud == 565-365){return true;} else {return false;}" fullword ascii
    $s11 = "return UFL.size;" fullword ascii
    $s12 = "if (x >= YFhQH.length) {break;}" fullword ascii
    $s13 = "function dpYsXjktA(HoddoqIFpHM) {" fullword ascii
    $s14 = "return YhuWojL(Kc,WtAfI[971-965]+WtAfI[638-631]+WtAfI[325-317]);" fullword ascii
    $s15 = "function ItYg(VmJsV) {" fullword ascii
    $s16 = "function ktSM(zuUVh) {" fullword ascii
    $s17 = "function UvyulJQmH(gaMUv) {" fullword ascii
    $s18 = "function aIyu(QOsxC) {" fullword ascii
    $s19 = "return Zbcie.status;" fullword ascii
    $s20 = "return qWdfaD.position=656-656;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}