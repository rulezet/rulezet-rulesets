rule sig_20160526_d9731bd40d0648f2d1f3408995ff223c {
  meta:
    description = "datamaliciousorder - file 20160526_d9731bd40d0648f2d1f3408995ff223c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1636e4fcd2acaab67aa726b663bd82c2834536ab6aa32d66db6e137fe6b2aec"

  strings:
    $s1  = "function ooGAkDfnwjZE(XYYBZQnwmhMPw) {var LTuRXwiFyWxhM = MIFZJzNV.join(crbjoxWVKgDZhHl[0]);var ydfkvyphHFHHCX, VottSZKPbm, fQeD" ascii
    $s2  = "h.sin(385), 2) + Math.pow(Math.cos(385), 2) - 1))-699)) ExfNpPCSL += kXGACwlsQsaeYVsvdtQjct(ydfkvyphHFHHCX, VottSZKPbm);else Exf" ascii
    $s3  = "th.pow(Math.cos(419), 2) - 1))-549)) ExfNpPCSL += hn(ydfkvyphHFHHCX);else if (MrFUBCoQhxCpqui == (763 + Math.round((Math.pow(Mat" ascii
    $s4  = "function RfVjHBJUfABqemr(xuHPkEjc,AtYXzMvLogttCpYWMIpZY){return xuHPkEjc.indexOf(AtYXzMvLogttCpYWMIpZY);}" fullword ascii
    $s5  = "function jaFzpcg(yxoYfCEhZRaLGX,cblfP){return yxoYfCEhZRaLGX.charAt(cblfP);}" fullword ascii
    $s6  = "BCoQhxCpqui = RfVjHBJUfABqemr(LTuRXwiFyWxhM,jaFzpcg(XYYBZQnwmhMPw,WHftOJ++));PmXHKrzLjIS = vhwCkkfOkY<< (267 + Math.round((Math." ascii
    $s7  = "function hn(eGpcgzcLQgiwm){return String.fromCharCode(eGpcgzcLQgiwm);}" fullword ascii
    $s8  = "function YMuxl(GIykRLaRCFoybgPmF,YZBgmBL,HYAHKncOgJDERfw){return String.fromCharCode(GIykRLaRCFoybgPmF,YZBgmBL,HYAHKncOgJDERfw);" ascii
    $s9  = "function ooGAkDfnwjZE(XYYBZQnwmhMPw) {var LTuRXwiFyWxhM = MIFZJzNV.join(crbjoxWVKgDZhHl[0]);var ydfkvyphHFHHCX, VottSZKPbm, fQeD" ascii
    $s10 = "NpPCSL += YMuxl(ydfkvyphHFHHCX, VottSZKPbm, fQeDRiRnTrUIiUImhxHZY);} while (WHftOJ < XYYBZQnwmhMPw.length);return ExfNpPCSL;}" fullword ascii
    $s11 = "function YMuxl(GIykRLaRCFoybgPmF,YZBgmBL,HYAHKncOgJDERfw){return String.fromCharCode(GIykRLaRCFoybgPmF,YZBgmBL,HYAHKncOgJDERfw);" ascii
    $s12 = "function kXGACwlsQsaeYVsvdtQjct(HBcDjsFKbXnUhG,DcvPgYWQEEXsqIL){return String.fromCharCode(HBcDjsFKbXnUhG,DcvPgYWQEEXsqIL);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}