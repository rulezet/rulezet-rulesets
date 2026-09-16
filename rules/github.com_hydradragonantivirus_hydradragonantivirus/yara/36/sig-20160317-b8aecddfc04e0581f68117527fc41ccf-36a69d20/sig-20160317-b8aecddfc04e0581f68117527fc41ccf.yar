rule sig_20160317_b8aecddfc04e0581f68117527fc41ccf {
  meta:
    description = "datamaliciousorder - file 20160317_b8aecddfc04e0581f68117527fc41ccf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81d7fa78692da8fc15be18f876141f14107f0ceef1c0ac6c352243bcab74377a"

  strings:
    $x1 = "var m = \"n!\";var gHd = \"6iRV7\".charAt(1);var ZH = \"Ra5JlP\".charAt(1);var TmK = \"\\x20ag\";var yj = \"\\x20t\\x72y\";var t" ascii
    $s2 = ") + (VC) + (pccxN) + (cjAL);}else{WScript.Echo((w1) + (tgotB) + (yj) + (TmK) + (ZH) + (gHd) + (m));}" fullword ascii
    $s3 = "return CB - j;}var acc = false;for (var N = 0; N < 10; N++){" fullword ascii
    $s4 = "}}if (acc){JejyO = BACaz[(zORLy) + (A0) + (vqnjO) + (rGiB) + (x0) + (a) + (KwMZf) + (MNBN) + (nPzX) + (Xe)]((U) + (Fs) + (HLV)) " ascii
    $s5 = "sQm) + (cvLX) + (H) + (JZgJ);};function qhY(){return 22;};function FHQjm(){" fullword ascii
    $s6 = "var L = new this[(Y) + (VAK)]();" fullword ascii
    $s7 = "c), (l) + (f) + (b0) + (b1) + (piGb) + (MR) + (XrqNB) + (hHyA) + (LhgzK), false);rWOX[(iBzT) + (gFQ)]();while (rWOX[(s) + (emf) " ascii
    $s8 = "(JxGN));function JJG(Mq){BACaz[(ir)](Mq, 0, 0);};function zMr(){return (oH) + (RnkZ) + (ISDBB);};function b(){return (WXqbu) + (" ascii
    $s9 = "acc = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and all of them
}