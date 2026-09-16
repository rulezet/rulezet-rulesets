rule sig_20160316_308193875adf47d7ba99304f49fc144c {
  meta:
    description = "datamaliciousorder - file 20160316_308193875adf47d7ba99304f49fc144c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5b75e7f34ea740a29a8e6e16ea68df8146f25dabdae21b60e5a7b4d4b05b2e8"

  strings:
    $s1 = "while (mmuvjT[qOkyphNsc + onaKuLUnKyg + duINnEGSOZ + fJXtadXDPQspy + UFDjRf] < 4 ) {WScript[Pxpb + Hmjn](1000)};" fullword ascii
    $s2 = "+ uOgnTSLH + UkwoiIkxn + amlGh + gxgL + rejgEcvcp + PFgoNgNDycYhn + XJoxJUqalwECsf + AKckwA + ElguYlFJCqOGkQ + OtiBJxlNo, false)" ascii
    $s3 = "function oRKrIkXUK(n){return aKez + pZQNwOMrfWNWm + ozsCqTvRQalAhN + KrRJYbhGVNl + JzWmNJXLR + JfyXHbalQiu + rORvg;}" fullword ascii
    $s4 = "function iLmHKfPkm(kiBzPq){COglFzNo[IrUJVBZyjpRXNcc + NddnCDOBX + GIEoAwFetY](kiBzPq, 0, 0);}" fullword ascii
    $s5 = "mmuvjT[oSWvKyXhSG + DwnnxJiumgZSg](yJvmrKTIleM + vqlxIfvBOZ, DhewNuwBVSy + XQfHbNHLrqgMES + mGMHnFEkJle + IWuobBvpq + EvzEgstDg " ascii
    $s6 = "var bIUqccmjZDnFqMl = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}