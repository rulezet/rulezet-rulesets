rule sig_20170507_0d258992733e8a397617eae0cbb08acc {
  meta:
    description = "datamaliciousorder - file 20170507_0d258992733e8a397617eae0cbb08acc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ac099dc7c74b0cd7852c947f3ef370e16d8e9cb6fe2bf8b2d5de94dedba3f38"

  strings:
    $s1 = "if ((bLGgrdCMRovlpnx != (496000-4960*OlwpPLsvRDhBKQEV)/4960) && (bLGgrdCMRovlpnx != (1009550-8275*OlwpPLsvRDhBKQEV)/8275) && (iy" ascii
    $s2 = "MwbtAxWPOohYzjGv(hxEobzlsRgNfcdX) == true) && (iyMwbtAxWPOohYzjGv(OlwpPLsvRDhBKQEV) == false)) { IGhuToEwXlJBQPS += String.fromC" ascii
    $s3 = "return KgJtXdpCLGQOuRMmYeV.replace(RegExp(vPsiWmlGbuYgxoeO, \"g\"), \"\"); }" fullword ascii
    $s4 = "function JIUFoiVePNXYTRaOyB(vPsiWmlGbuYgxoeO) { " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}