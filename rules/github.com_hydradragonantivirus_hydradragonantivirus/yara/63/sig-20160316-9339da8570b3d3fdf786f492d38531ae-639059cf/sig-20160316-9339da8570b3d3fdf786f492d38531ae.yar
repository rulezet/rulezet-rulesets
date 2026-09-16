rule sig_20160316_9339da8570b3d3fdf786f492d38531ae {
  meta:
    description = "datamaliciousorder - file 20160316_9339da8570b3d3fdf786f492d38531ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a805a137db19fe69d5a9d597bcbb938725f385f5be9baebc421a42b2d29dde9d"

  strings:
    $s1 = "while (yGl[BWLbCLHpkFuEu + GbQxdEHy + VOSODiFtBkSkEW + wmmuXpc + LPLrP] < 4 ) {WScript[BkkoRQ + KfcgWVuOFtKO](1000)};" fullword ascii
    $s2 = "function KrZdZntlweuQaGL(rDUAPOu){xbQPFlwkvIAK[aJNQhuP + ARdwUqiGYMEe](rDUAPOu, 0, 0);}" fullword ascii
    $s3 = "function gxtxgkZGemmA(n){return wKD + KaUqmuI + GUyeOw + MZOWV + fMHdCqAZGOyeFxW + RjpPSxfQaT + XlXUDA + nsvZO;}" fullword ascii
    $s4 = "+ WgSFQceBD + KnUWqzPQQqRj + wmZGfRxffzrTo + cRlTiJgiiXTCc + LZfA + wEDi + sFLvcTusR + JywyYxm, false);" fullword ascii
    $s5 = "yGl[yaKDR + sicIIkixCNNey](VAljO + LawlJoCjMcGp, EsHelaftSehaY + idXHRYXC + zkNbwQ + tPkVtKOTS + eFAUfcAoGOUQWB + AWNRqYtLOppMw " ascii
    $s6 = "var AYIjjE = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}