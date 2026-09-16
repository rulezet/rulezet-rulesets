rule sig_20160316_0cfee96ae20f3fb9695f406cbbf0e67e {
  meta:
    description = "datamaliciousorder - file 20160316_0cfee96ae20f3fb9695f406cbbf0e67e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c4773c739cc5f7e6ce15fc0bb4167337941fbdf2431f5f47cbbd2a5ee2bc326"

  strings:
    $s1 = "while (WMmh[PpeJjyqeq + qjWwoNcJD + oxzHZdJggjuK + kGlOiOCfie] < 4 ) {WScript[wZZxrpu + Ntgqpzf + VSPix](1000)};" fullword ascii
    $s2 = "WMmh[EikmgZhdg + eyBtIRIIEr](KTArJlIkDd + BacaqjwmdmZ, sfctXe + KmVQmNlDvB + xAgOFXvHHEdVnW + qHzbFZazBkVUuzh + OgmRXGeyef + zAJ" ascii
    $s3 = "FynXnUPSMaL + vlnRozKMY + QQDRbfbn + gwy + jRX + gwpCWtNhwSj + ugqm + XkMHTEbpV, false);" fullword ascii
    $s4 = "function hOWJ(n){return pnZyUcSonEIX + ckymhFMwClmva + OsGZWFlW + JOzz + otIxLd + BJVYvKiJELYG + LldQ + JFqvkmXLJps + fAuvXpdNol" ascii
    $s5 = "function hOWJ(n){return pnZyUcSonEIX + ckymhFMwClmva + OsGZWFlW + JOzz + otIxLd + BJVYvKiJELYG + LldQ + JFqvkmXLJps + fAuvXpdNol" ascii
    $s6 = "function JUmzFcZbBrqR(pbK){WmNbPhMhQkNFB[NsnXwBcsjrBnqQ](pbK, 0, 0);}" fullword ascii
    $s7 = "var onpoCxRb = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}