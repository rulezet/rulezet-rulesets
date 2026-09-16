rule sig_20160324_355c2fc4e41e0ac591d6178e5d890355 {
  meta:
    description = "datamaliciousorder - file 20160324_355c2fc4e41e0ac591d6178e5d890355.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4339f65b77954a791ce418aa7a3fa6ac0a688ccdd6a6b2bb4a7c3bfa2ab6c0df"

  strings:
    $s1  = "return WScript.CreateObject(TmDvE);" fullword ascii
    $s2  = "return DrrKWON[0] + DrrKWON[2] + DrrKWON[4] + \".F\" + DrrKWON[7] + DrrKWON[9] + DrrKWON[12] + DrrKWON[14];" fullword ascii
    $s3  = "var Jg = true  , nfqH = Mjs[7] + Mjs[9] + Mjs[11];" fullword ascii
    $s4  = "var Mjs = (\"2.XMLHTTP gZotden mHmVm XML ream St xUhMiukG AD cnQiZWw O yFBP D\").split(\" \");" fullword ascii
    $s5  = "var DrrKWON = ViZPb(jwXSfMELdY+\" \"+\"System Qb QLofI Obj QRhSfk ect KpAvLft RIqhk\", \" \");" fullword ascii
    $s6  = "lyQA.open(ZoQfG,wUheO,false);" fullword ascii
    $s7  = "function fHJQoPFGz(YmMyGxzrebK) {" fullword ascii
    $s8  = "return BONg[sooNRO[0]];" fullword ascii
    $s9  = "function jzuX(LztEG,clPWY) {" fullword ascii
    $s10 = "return TjiMq.status;" fullword ascii
    $s11 = "function MkPV(PeSEa) {" fullword ascii
    $s12 = "function eNQvH(pBauBqId,DiRx) {" fullword ascii
    $s13 = "return Mev.size;" fullword ascii
    $s14 = "return clZzYg/*mySUhNDKmLG1kQlPlalms9AMQ*/.position=379-379;" fullword ascii
    $s15 = "function JZuH(WqJRK,wUheO,ZoQfG) {" fullword ascii
    $s16 = "if (LbtUq > 195228-992){return true;} else {return false;}" fullword ascii
    $s17 = "function WFTX(xQvkH) {" fullword ascii
    $s18 = "function cKutJZRY(Mev) {" fullword ascii
    $s19 = "return hLHuNZA(XF,iWmWX[912-906]+iWmWX[375-368]+iWmWX[475-467]);" fullword ascii
    $s20 = "function KHUT(nZjdt,TTLnW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}