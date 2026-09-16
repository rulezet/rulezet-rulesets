rule sig_20160316_6497b8c3cee825b967b6848b2cd4d888 {
  meta:
    description = "datamaliciousorder - file 20160316_6497b8c3cee825b967b6848b2cd4d888.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bfd725326c1f4fee2d2667f06b8d0f926f372cecc3013733afec3e1b079f68a"

  strings:
    $s1 = "while (NXVOpxbhmuHEo[IMllGQ + gCKDDeZBeg + HYHhMisOpOQ + mMWp + WLlgaHbNQtKNm] < 4 ) {WScript[QUFEhtEvjIwYjp + qoySvKPie + OyiWW" ascii
    $s2 = "while (NXVOpxbhmuHEo[IMllGQ + gCKDDeZBeg + HYHhMisOpOQ + mMWp + WLlgaHbNQtKNm] < 4 ) {WScript[QUFEhtEvjIwYjp + qoySvKPie + OyiWW" ascii
    $s3 = "function nlPszyMDBRb(n){return CUVRbaJ + mNOcKUIau + PSswtBVs + ksNjB + sihAPkEriYl + iCmxbGGHu + bQosjbWOPQ;}" fullword ascii
    $s4 = "var rKY = new Date();" fullword ascii
    $s5 = " + MgJPa + qbigOW + PLdFlvlTNECR + jZzqpJmyR + qqfFO + IbrgQdkNs + PwSfPkCAbzU + oAf + kUpGqYx + LTUJuqgpZ, false);" fullword ascii
    $s6 = "NXVOpxbhmuHEo[DjaqMm + wTLqRTixQXPO + yEvRwOUPW](wTP + MEcNZeGwbZbg, fKGFjXlGZUs + Vxko + IbHAxVJY + FtRwUrxQH + hwNbFEKGtsZkchP" ascii
    $s7 = "function AYWcasKV(cqOAhJnSusqJQG){SbHZuDxfolscED[YlI](cqOAhJnSusqJQG, 0, 0);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}