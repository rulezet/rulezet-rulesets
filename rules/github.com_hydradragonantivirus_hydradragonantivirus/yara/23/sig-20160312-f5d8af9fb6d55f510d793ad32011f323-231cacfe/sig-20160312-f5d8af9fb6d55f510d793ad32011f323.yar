rule sig_20160312_f5d8af9fb6d55f510d793ad32011f323 {
  meta:
    description = "datamaliciousorder - file 20160312_f5d8af9fb6d55f510d793ad32011f323.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6aa088860ee34e9f754fb90d5b8d57fb0b54bd7ac316f05e70447e99d31e0d20"

  strings:
    $s1  = "return owGXnYL[0] + owGXnYL[2] + owGXnYL[4] + \".F\" + owGXnYL[7] + owGXnYL[9] + owGXnYL[12] + owGXnYL[14];" fullword ascii
    $s2  = "var Md = true  , jiOh = AmJ[7] + AmJ[9] + AmJ[11];" fullword ascii
    $s3  = "var owGXnYL = \"Sc RLEEWPf r SfRxhbosA ipting BGGXEMV GaV ile PDZiacGPSFAgjg System ao gWQWY Obj dwYqdL ect TanFVVI\".split(\" " ascii
    $s4  = "var AmJ = (\"2.XMLHTTP xTDENYM SOcZx XML ream St PxGJhZaa AD aReXywe O TGmI D\").split(\" \");" fullword ascii
    $s5  = "IeErC.open(xpyIV,ibIzS,false);" fullword ascii
    $s6  = "if(k>=v.length) {break;}" fullword ascii
    $s7  = "function vqPe(NHUQw) {" fullword ascii
    $s8  = "function mzyWO(UzFAos) {" fullword ascii
    $s9  = "if (z >= WBlvI.length) {break;}" fullword ascii
    $s10 = "return uZJGSbv(Rw,dyPKG[165-159]+dyPKG[606-599]+dyPKG[874-866]);" fullword ascii
    $s11 = "return JbSVmj.position=989-989;" fullword ascii
    $s12 = "if (mlVPy > 164868-220){return true;} else {return false;}" fullword ascii
    $s13 = "function rxyj(IeErC,ibIzS,xpyIV) {" fullword ascii
    $s14 = "return QYttM.status;" fullword ascii
    $s15 = "function NzFc(QYttM) {" fullword ascii
    $s16 = "return bbo.size;" fullword ascii
    $s17 = "function aOrY(QoVGb) {" fullword ascii
    $s18 = "function nxrnw(JbSVmj) {" fullword ascii
    $s19 = "function PiMSdcIOq(chNEjpzmDHq) {" fullword ascii
    $s20 = "return CKVP.ExpandEnvironmentStrings(exfgX);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}