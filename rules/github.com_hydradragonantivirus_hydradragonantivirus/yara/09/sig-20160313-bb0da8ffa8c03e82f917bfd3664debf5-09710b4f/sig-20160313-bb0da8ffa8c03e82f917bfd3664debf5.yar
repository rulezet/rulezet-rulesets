rule sig_20160313_bb0da8ffa8c03e82f917bfd3664debf5 {
  meta:
    description = "datamaliciousorder - file 20160313_bb0da8ffa8c03e82f917bfd3664debf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a02ae1b4cd6dba7de980580dc7db3f48e21f2a4ff7785fd88d0317878d55759a"

  strings:
    $s1  = "var dB = true  , XyQQ = ipP[7] + ipP[9] + ipP[11];" fullword ascii
    $s2  = "return mEBorGy[0] + mEBorGy[2] + mEBorGy[4] + \".F\" + mEBorGy[7] + mEBorGy[9] + mEBorGy[12] + mEBorGy[14];" fullword ascii
    $s3  = "var ipP = (\"2.XMLHTTP xdZpBUy qQIth XML ream St zHBBlVEL AD QuAVsQi O LATb D\").split(\" \");" fullword ascii
    $s4  = "CUXPY.open(hKEiM,lJHoT,false);" fullword ascii
    $s5  = "var mEBorGy = \"Sc hwpbBFx r CdHjXDwKF ipting DVStMJC VmA ile koUtXwQtROckFZ System bJ kBpRL Obj ayfVML ect dWPJFpN\".split(\" " ascii
    $s6  = "if(r>=G.length) {break;}" fullword ascii
    $s7  = "XKx = r; break; " fullword ascii
    $s8  = "function HLvXXbr(mvJK) {" fullword ascii
    $s9  = "return VDIKY.status;" fullword ascii
    $s10 = "return new ActiveXObject(eiMtqF);" fullword ascii
    $s11 = "if (ofdcu == 1188-988){return true;} else {return false;}" fullword ascii
    $s12 = "function PdZQ(LRGlM) {" fullword ascii
    $s13 = "function Fieq(VDIKY) {" fullword ascii
    $s14 = "function Okue(wSCRJ) {" fullword ascii
    $s15 = "function GKmlxHKs() {" fullword ascii
    $s16 = "return GOK.size;" fullword ascii
    $s17 = "return TUEdVkh(ge,QqqzZ[899-893]+QqqzZ[923-916]+QqqzZ[624-616]);" fullword ascii
    $s18 = "return tLjM.ExpandEnvironmentStrings(IENPI);" fullword ascii
    $s19 = "function gUrnOTplK(QyOwhDxlvCQ) {" fullword ascii
    $s20 = "function sWJa(QZBJv) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}