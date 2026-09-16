rule sig_20160514_736e1e7c43853b530f2faeaeef303fb0 {
  meta:
    description = "datamaliciousorder - file 20160514_736e1e7c43853b530f2faeaeef303fb0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28fc51f6ab32174fa541f46b9362a48c1f9b2cca11973c92d2d44cf7f1d9104"

  strings:
    $s1  = "while (TollqxuO < FcTv - (4453 + 1190 - 5641)) {" fullword ascii
    $s2  = "return gEPdk;" fullword ascii
    $s3  = "function IjEVF(rtwjdld, kdkndmd) {" fullword ascii
    $s4  = "return STenhF;" fullword ascii
    $s5  = "function OODeDiz() {" fullword ascii
    $s6  = "return QfhusyZk;" fullword ascii
    $s7  = "return AXlSMESD;" fullword ascii
    $s8  = "function RbHgsm() {" fullword ascii
    $s9  = "function NPyYw() {" fullword ascii
    $s10 = "return zAMewr;" fullword ascii
    $s11 = "return ZwDHtXK[ImeiMSr];" fullword ascii
    $s12 = "function Gews() {" fullword ascii
    $s13 = "function DsvpN(EOqCJ, vSTCDs) {" fullword ascii
    $s14 = "return exzJu;" fullword ascii
    $s15 = "function exuo() {" fullword ascii
    $s16 = "var FPQCsvw = String;" fullword ascii
    $s17 = "function urFPl() {" fullword ascii
    $s18 = "function eRFQUD() {" fullword ascii
    $s19 = "function dLSxu() {" fullword ascii
    $s20 = "function UuEH(Jqzz, jgBwHve) {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}