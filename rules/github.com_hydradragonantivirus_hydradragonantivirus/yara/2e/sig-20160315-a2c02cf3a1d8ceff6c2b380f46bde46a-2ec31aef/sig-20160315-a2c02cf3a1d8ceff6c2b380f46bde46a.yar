rule sig_20160315_a2c02cf3a1d8ceff6c2b380f46bde46a {
  meta:
    description = "datamaliciousorder - file 20160315_a2c02cf3a1d8ceff6c2b380f46bde46a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79277b3f98682ab35fe985eeed3a41bb95cb9875bdeb972d1d7901811c67f860"

  strings:
    $s1 = "function NoUsszEvKlkTVv(KzwW){WshShell[kswuAsYCeApHE + UcLgLaH](KzwW, 0, 0);}" fullword ascii
    $s2 = "while (mTyebzM.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "XGI + fOKhulZbKWzS + SIxpU + eVBRmfPKE + JOFzlUOkMq + BPUY + DLIBGTFUzGhEWRX + koSAPkImYtSUD, false);" fullword ascii
    $s4 = "function RTcpKf(n){return SsGmmPgWg + MZWwPLwoYRTKn + dNthK + CQw + jtWkQoyn + ESAwizLYf + FSpvSGf + TXAPQSjWKm;}" fullword ascii
    $s5 = "mTyebzM[lLlaWHUCpMn + GWtIpZYuQqsNb + nDIVNdmQB](XjNEt + ECmjeSWGPQCBE, AVf + tZxFzNQrS + RyWFxxJewODhg + ULBYr + FASx + ucTLhSd" ascii
    $s6 = "var ezgsfxb = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}