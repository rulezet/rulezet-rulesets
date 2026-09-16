rule sig_20160317_96c121ced92465331b2555cad746f7f4 {
  meta:
    description = "datamaliciousorder - file 20160317_96c121ced92465331b2555cad746f7f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69761890e6c69a53fc250f0f772a73978d94dd4fe0848a6d9e4ab315ef4bc063"

  strings:
    $s1 = "var PU = \"\\x6e!\";var qwA = \"gai\";var bg = \"y\\x20a\";var jpiR = \" \\x74r\";var r0 = \"9MK,W5\".charAt(3);var ybKQi = \"s" ascii
    $s2 = "Ta) + (Co) + (cC) + (s0) + (UyFUw) + (QN) + (wDHZ) + NDZ ? (NqZ) + (cSF) : (r) + (agVp) + (Y0) + (bWFU);}else{WScript.Echo((TnRR" ascii
    $s3 = "}}if (NDZ){VIm = FfLb[(LWOF) + (t) + (wXoq) + (Mw) + (Fx) + (j) + (IYL) + (K) + (LQ) + (k0)]((Wakt) + (bLlv) + (QklcJ)) + (w) + " ascii
    $s4 = "return xzyL - Y;}var NDZ = false;for (var Tdev = 0; Tdev < Ow() * 1; Tdev++){" fullword ascii
    $s5 = ");};function Cof(){return (MZ) + (ks) + (kBkA) + (O0) + (b0);};function Ow(){return 22;};function smby(){" fullword ascii
    $s6 = ") + (wrQFd) + (Iu) + (Rcg));function dWnBr(jERZ){FfLb[(z)](jERZ, 0, 0);};function WwN(){return (tsw) + (Vqad) + (V) + (Dav) + (o" ascii
    $s7 = "(QQN), (ZQP) + (HP) + (i) + (m) + (lRA) + (YFXir) + (LqCh) + (e) + (kbM) + (g0) + (UzqS), false);O[(Hk)]();while (O[(MHivC) + (Q" ascii
    $s8 = "var b = new this[(HA)]();" fullword ascii
    $s9 = "NDZ = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}