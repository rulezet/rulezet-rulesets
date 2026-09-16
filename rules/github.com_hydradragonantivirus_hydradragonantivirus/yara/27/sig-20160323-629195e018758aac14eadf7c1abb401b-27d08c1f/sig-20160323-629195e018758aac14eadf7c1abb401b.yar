rule sig_20160323_629195e018758aac14eadf7c1abb401b {
  meta:
    description = "datamaliciousorder - file 20160323_629195e018758aac14eadf7c1abb401b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37cb66380622e550e2d4628a4ce4dfa325a9ce93045364560d73e207ce3490df"

  strings:
    $s1  = "return WScript.CreateObject(CXecC);" fullword ascii
    $s2  = "var iN = true  , EdMN = Yum[7] + Yum[9] + Yum[11];" fullword ascii
    $s3  = "return JekcJFM[0] + JekcJFM[2] + JekcJFM[4] + \".F\" + JekcJFM[7] + JekcJFM[9] + JekcJFM[12] + JekcJFM[14];" fullword ascii
    $s4  = "var JekcJFM = hxqVG(VmIgmLDuqi+\" \"+\"System mv ZuViE Obj vwVoNV ect fQQfERl MGUfD\", \" \");" fullword ascii
    $s5  = "qJtQ.open(ZzyMA,LFmsK,false);" fullword ascii
    $s6  = "var Yum = (\"2.XMLHTTP bAiDXlc EKJHI XML ream St shiSFgan AD pCjpReJ O oKBl D\").split(\" \");" fullword ascii
    $s7  = "return OyTaWA/*pisqQZuSq1KmLTBNUkweO0oGQ*/.position=372-372;" fullword ascii
    $s8  = "if (E >= usRIA.length) {break;}" fullword ascii
    $s9  = "return nclLF;" fullword ascii
    $s10 = "function fVqJ(gWxyP,LFmsK,ZzyMA) {" fullword ascii
    $s11 = "function yuFLHkUkX(AozAxdoRfiP) {" fullword ascii
    $s12 = "function WbJx(MPaIu) {" fullword ascii
    $s13 = "return fEKJe.status;" fullword ascii
    $s14 = "function zfIC(wVxkJ) {" fullword ascii
    $s15 = "OSj = M; break; " fullword ascii
    $s16 = "function fxYT(RlUmb,IYqqi) {" fullword ascii
    $s17 = "function zONLfWz(gtsi) {" fullword ascii
    $s18 = "function HKwc(IpVhO) {" fullword ascii
    $s19 = "function UWbJOAv(AlXN,hKiia) {" fullword ascii
    $s20 = "function nIcKWhIJc(LSazc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}