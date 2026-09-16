rule sig_20160317_d70b88142a27e8ce84754ec1a74835a2 {
  meta:
    description = "datamaliciousorder - file 20160317_d70b88142a27e8ce84754ec1a74835a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8e8da14ce30b0e0e2ef3e6c242a4f02fcea31cb2fd53204efd0bda58d0edf0f"

  strings:
    $s1  = "var f0 = \"\\x69n!\";var qd = \"ga\";var qWij = \"try a\";var ZyDm = \"e, \";var vMA = \"\\x61s\";var IQCFu = \"P\\x6c\\x65\";va" ascii
    $s2  = "KhkT = WScript[(Cb) + (XxR) + (k) + (hPCQT)]((KmF) + (SLM) + (MAHCU) + (oZXEG));function o(EYxU){KhkT[(AyP)](EYxU, 0, 0);};funct" ascii
    $s3  = ");}else{WScript.Echo((IQCFu) + (vMA) + (ZyDm) + (qWij) + (qd) + (f0));}" fullword ascii
    $s4  = "return mpyn - TJ;}var ZGZX = false;for (var RwQuR = 0; RwQuR < SZkHF() * 1; RwQuR++){" fullword ascii
    $s5  = "}}if (ZGZX){GkhOf = KhkT[(hvvVq) + (IQ) + (GM) + (mqdHq) + (K0) + (kb) + (Ats) + (uGV)]((gXIeH) + (MjA) + (OH)) + (hN) + (jFJi) " ascii
    $s6  = "ion RCr(){return (Qs) + (a) + (nA) + (U) + (K) + (j);};function km(){return (Cb) + (XxR) + (k) + (hPCQT);};function SZkHF(){retu" ascii
    $s7  = "var UGp = new this[(V) + (QmyK) + (xIz) + (UG)]();" fullword ascii
    $s8  = "+ (Uj) + (NJuG) + (P) + (rEFsz) + (XF) + (hvMO) + (lVKUX) + (jzU) + (bQy) + (Mq0) + (UdoQ), false);YTsS[(nQWpX)]();while (YTsS[(" ascii
    $s9  = "rn 22;};function pnDuj(){" fullword ascii
    $s10 = "ZGZX = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}