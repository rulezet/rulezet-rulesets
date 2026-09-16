rule sig_20160316_e8085cbcf7f24a20b081e44ac9dcfa81 {
  meta:
    description = "datamaliciousorder - file 20160316_e8085cbcf7f24a20b081e44ac9dcfa81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3aa4338b1780bb4361a0eaf8d656ab5899742ba2109997509b8bdcec3d73d79c"

  strings:
    $s1  = "while (bnzWSWLjqNfWnMJ[hicomMJqHFUFILJ + dKPd + qjdEXYGkQnoA + RYuQoKjDES] < 4 ) {WScript[jVaHNoicyjVQ + fNTjjhtZlCV](1000)};" fullword ascii
    $s2  = "RxAowDiKp = WScript[eqZXZKaixGh + bQXDYiKQyMAjPws + PHtMcKqHzKc + bSZepuF + Aiyy + phddcmvWAX + mPDJBALjlvIYe](FAEeiQmsnOp + Cuq" ascii
    $s3  = "function wclsr(n){return bAlEqaubwR + Vshkcu + zCsofK + AcByWWvlsIfvSYa + FUDmuHugPlxaF + SlPdQzFpDctNvc + NnUdFVKblY + cvLogLL;" ascii
    $s4  = "function wclsr(n){return bAlEqaubwR + Vshkcu + zCsofK + AcByWWvlsIfvSYa + FUDmuHugPlxaF + SlPdQzFpDctNvc + NnUdFVKblY + cvLogLL;" ascii
    $s5  = "sZuEv + DybSwSeYU + aPCcN + URbDxGhLwvvCz + DgUdXUqaFlA + choP + dMYGFfNYlmE);" fullword ascii
    $s6  = "function HQHRtcEkPEra(BuTgAv){XFMpya[ezerUB + NBZd](BuTgAv, 0, 0);}" fullword ascii
    $s7  = "var JbavsG = new Date();" fullword ascii
    $s8  = "var SOlO = \"co\";" fullword ascii
    $s9  = "eZbU, false);" fullword ascii
    $s10 = "var choP = \"e\";" fullword ascii
    $s11 = "bnzWSWLjqNfWnMJ[SIZzKbjfEUHLRx + YqgUsFmNdNP](mBdTBvyi + UZvnjVCijPm, lzvFZApiMDG + hCaHKYnqceNiOIr + xhPPyOU + uyAKAzbOpUQ + FW" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}