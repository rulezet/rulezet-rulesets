rule sig_20160316_15551a82ae312c286100352fd64c7c08 {
  meta:
    description = "datamaliciousorder - file 20160316_15551a82ae312c286100352fd64c7c08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97c4f585439c8d76e746702641b92ec1e956fd1bfbb7567c6189c2603a6924fb"

  strings:
    $s1 = "while (vVxJUmT[KFwdUXumuhVIuW + VQEXcsDarRErplq + baUAEDcwWy + fMTvPwoYzpLJ] < 4 ) {WScript[MDljNaAe + bCHSx + JhSsrsBisnc](1000" ascii
    $s2 = "while (vVxJUmT[KFwdUXumuhVIuW + VQEXcsDarRErplq + baUAEDcwWy + fMTvPwoYzpLJ] < 4 ) {WScript[MDljNaAe + bCHSx + JhSsrsBisnc](1000" ascii
    $s3 = "vVxJUmT[KtUNkbKAYPOS + StAwZkViRKjYA](VVdyeijnd + BUCNRNmIgDr, qSmnjBZD + RHDB + VBbBIWOfTOqsQ + adbsBINI + Pniymyrvys + wzPipBc" ascii
    $s4 = "function LDCPZFZ(n){return cmHcMJwyTLnu + CCPXWV + slvQ + ywgWjMtAFpAzY + XJuwcV + DHV + ciXwpsuI;}" fullword ascii
    $s5 = "function AEfDwiWAba(xYZlsXDQ){EHtsuWuMNShwLLv[rarzffimo + DLpJDGUXkpeZfA](xYZlsXDQ, 0, 0);}" fullword ascii
    $s6 = "var NXbnKyMspfhuvcs = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}