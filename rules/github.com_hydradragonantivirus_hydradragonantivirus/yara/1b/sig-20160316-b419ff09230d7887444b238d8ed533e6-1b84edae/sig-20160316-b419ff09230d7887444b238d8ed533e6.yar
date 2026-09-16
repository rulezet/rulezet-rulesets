rule sig_20160316_b419ff09230d7887444b238d8ed533e6 {
  meta:
    description = "datamaliciousorder - file 20160316_b419ff09230d7887444b238d8ed533e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "163fffa7c58c315ac688a910a690060d9a9bc703d0037d8e90878ef65795470c"

  strings:
    $s1 = "function hrT(n){return JwvtUpvKHDVnw + HTCXdLGaBZBQ + ybONMk + AgXgNSHopAfqbO + zwOGVECMvUhGeT + lOuTrrjdHmsM + texBnrhXLMW + cZ" ascii
    $s2 = "function hrT(n){return JwvtUpvKHDVnw + HTCXdLGaBZBQ + ybONMk + AgXgNSHopAfqbO + zwOGVECMvUhGeT + lOuTrrjdHmsM + texBnrhXLMW + cZ" ascii
    $s3 = "while (odLuPejOONnyPmH[aonsjQPERjeh + ORKHMFBqAA + xisNPT + VrqvDKZWDH + NcAMdyulzvs] < 4 ) {WScript[cORMYRdmXSgBpa + LOXEEIIbNT" ascii
    $s4 = "while (odLuPejOONnyPmH[aonsjQPERjeh + ORKHMFBqAA + xisNPT + VrqvDKZWDH + NcAMdyulzvs] < 4 ) {WScript[cORMYRdmXSgBpa + LOXEEIIbNT" ascii
    $s5 = "nqnRByzEOY + VSeDVrFjfbmGFxg + sPABUuVXegEF + opBwpmpnS + SBQYEfdN + dval + QWHXD + UwIjPiVcwAFyBS, false);" fullword ascii
    $s6 = "function dDLZTCkJxGOhT(BCfuesB){MvHNTHG[ZYJGXCxLDZjxYN + tmGYULgw](BCfuesB, 0, 0);}" fullword ascii
    $s7 = "var nNnvWL = new Date();" fullword ascii
    $s8 = "odLuPejOONnyPmH[JKjwbCHYYbD + zCYyDytJIdCp](hyZpMjRm, giLCAVvHRHq + HWlVgL + YkJwfxGhCYpe + smVbrYO + OwJpc + QXFGgvbtqpIf + geK" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}