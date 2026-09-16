rule sig_20160317_c65100cdd18b63b42b714b4d0cda3a4e {
  meta:
    description = "datamaliciousorder - file 20160317_c65100cdd18b63b42b714b4d0cda3a4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62b3a3fc97d2e352666d3f41220fac0ceae323fe2fb6e6fd5b2ce2ff8cd1865a"

  strings:
    $s1  = "var wHQ = \"g\\x61\\x69n\\x21\";var lixpQ = \"r\\x79 \\x61\";var vF = \"\\x20t\";var oOnUY = \"ase\\x2c\";var bbb = \"Ple\";var " ascii
    $s2  = "}}if (G){wOBt = gKnGK[(vA) + (UAkax) + (eKYf) + (VRqY) + (bUJkI) + (Hufvw) + (nt) + (xTttV)]((xnpC) + (sWU) + (tthyg)) + (V) + (" ascii
    $s3  = ");}else{WScript.Echo((bbb) + (oOnUY) + (vF) + (lixpQ) + (wHQ));}" fullword ascii
    $s4  = "Q[(vPoS)]();while (NgcQ[(wn) + (rAOS) + (SD) + (Xq)] < 4 ) {WScript[(VrFK) + (cU) + (I)](XW() * 10)};jjZg = WScript[v()]((Ie) + " ascii
    $s5  = "return ZAbg - zp;}var G = false;for (var VzcO = 0; VzcO < XW() * 1; VzcO++){" fullword ascii
    $s6  = "+ (vP) + (Tv) + (YVvhP);};function v(){return (Te) + (jI) + (IIkA) + (XYsSn) + (bqI) + (HG);};function XW(){return 22;};function" ascii
    $s7  = "+ (kGXC) + (z) + (EasqE) + (oHLIn) + (Ias));function Evna(tQDs){gKnGK[(YXLRy) + (hd)](tQDs, 0, 0);};function XRsz(){return (Eb) " ascii
    $s8  = "fcj), (wlMRG) + (pKoI) + (Pos) + (UySq) + (cvm) + (WyEu) + (SdFp) + (b) + (T) + (eefBs) + (vLJd) + (Ms) + (lr) + (k), false);Ngc" ascii
    $s9  = "var ska = new this[(Sp) + (Jjs)]();" fullword ascii
    $s10 = "G = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}