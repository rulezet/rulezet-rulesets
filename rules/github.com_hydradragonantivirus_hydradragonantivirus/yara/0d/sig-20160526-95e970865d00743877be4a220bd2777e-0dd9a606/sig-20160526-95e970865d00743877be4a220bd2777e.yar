rule sig_20160526_95e970865d00743877be4a220bd2777e {
  meta:
    description = "datamaliciousorder - file 20160526_95e970865d00743877be4a220bd2777e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "784ce2c52ca610624d14a33989a45dac4d103a9deac3f80ec1f493aa21f26c4e"

  strings:
    $s1  = "nd((Math.pow(Math.sin(963), 2) + Math.pow(Math.cos(963), 2) - 1))-820)) spsTYNMgoVXkScJz += yP(QbpFJVLvDIkNw);else if (nlIpj == " ascii
    $s2  = "th.round((Math.pow(Math.sin(32), 2) + Math.pow(Math.cos(32), 2) - 1))-839) | kdvGdCPOTdkPayngKnedgVXd<< (409 + Math.round((Math." ascii
    $s3  = "function CGYrVGvHfTkHw(tebnIAhItHBcP) {var DtgBPKzlTbhR = twcKfBBaBiMUasZbPOjvl.join(xITthKnwtHnEADmpi[0]);var QbpFJVLvDIkNw, kl" ascii
    $s4  = "function hPWWnUeEyRydcAiRLb(MPSoXXiTaJcla,KQscSpWZGvOC){return MPSoXXiTaJcla.charAt(KQscSpWZGvOC);}" fullword ascii
    $s5  = "function CTEUUF(YGawNRPaHacfu,IkeNTreqWwgnK,oYjwOXcSURBd){return String.fromCharCode(YGawNRPaHacfu,IkeNTreqWwgnK,oYjwOXcSURBd);}" ascii
    $s6  = "function yP(JvbITlIcDOgqofBKXYY){return String.fromCharCode(JvbITlIcDOgqofBKXYY);}" fullword ascii
    $s7  = "function CGYrVGvHfTkHw(tebnIAhItHBcP) {var DtgBPKzlTbhR = twcKfBBaBiMUasZbPOjvl.join(xITthKnwtHnEADmpi[0]);var QbpFJVLvDIkNw, kl" ascii
    $s8  = "QbpFJVLvDIkNw, klZgpc);else spsTYNMgoVXkScJz += CTEUUF(QbpFJVLvDIkNw, klZgpc, nJdMLzIfsxjcHpe);} while (rTvbCYx < tebnIAhItHBcP." ascii
    $s9  = "length);return spsTYNMgoVXkScJz;}" fullword ascii
    $s10 = "function oTzqnQdXyrMEu(lrRvOcvBdSOoB,PtdCbGFFollHlKvKcKFzpgj){return lrRvOcvBdSOoB.indexOf(PtdCbGFFollHlKvKcKFzpgj);}" fullword ascii
    $s11 = "function GnCdAmORcSaIhsnYBbzHu(dbFyZPshIkxujwUBuGDrrWY,AuVnIVxnVcaI){return String.fromCharCode(dbFyZPshIkxujwUBuGDrrWY,AuVnIVxn" ascii
    $s12 = "function GnCdAmORcSaIhsnYBbzHu(dbFyZPshIkxujwUBuGDrrWY,AuVnIVxnVcaI){return String.fromCharCode(dbFyZPshIkxujwUBuGDrrWY,AuVnIVxn" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}