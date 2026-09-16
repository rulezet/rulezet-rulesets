rule sig_20160525_85707d6aff3c47aef1cc5ad837ce27a1 {
  meta:
    description = "datamaliciousorder - file 20160525_85707d6aff3c47aef1cc5ad837ce27a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "099b165e9304e8b5b46acde3923544ec48d635521b00fddc2c1008e35b0b6c1c"

  strings:
    $s1  = "SEBC);else if (HIaLLLMUMHpkeyZTVsnZmcBW == (564 + Math.round((Math.pow(Math.sin(364), 2) + Math.pow(Math.cos(364), 2) - 1))-500)" ascii
    $s2  = "function OYxlIebo(XHWHIidzXlaIO) {var rihiyjtU = dXHWepwxRIZYWfU.join(kNSOXCyfPHxsfy[0]);var xEBGzkKvGWKMoOtovZbSEBC, WlvnLJ, ke" ascii
    $s3  = "function OKTEFTqOcLxDwz(OnUlsHmQTczC,jRgcorbEYbPC){return OnUlsHmQTczC.charAt(jRgcorbEYbPC);}" fullword ascii
    $s4  = "function nblDDzamJd(bAPYkIbswjrIuXLYxctGlx,ouoyRxdwUsTu){return String.fromCharCode(bAPYkIbswjrIuXLYxctGlx,ouoyRxdwUsTu);}" fullword ascii
    $s5  = ") FicIQrrzqoDwFoI += nblDDzamJd(xEBGzkKvGWKMoOtovZbSEBC, WlvnLJ);else FicIQrrzqoDwFoI += DGUXERTiZH(xEBGzkKvGWKMoOtovZbSEBC, Wlv" ascii
    $s6  = "function DGUXERTiZH(MDPufdPzoQGmsCVbFhxz,PdiLUkLdknpeHaIpqsRjd,XZKGgRcTNmIVVitrZMojEWA){return String.fromCharCode(MDPufdPzoQGms" ascii
    $s7  = "function tvrmtti(yPdFKwPbzAbdQKtxGtlYtcGu,XxXssfxHsAfMWyQ){return yPdFKwPbzAbdQKtxGtlYtcGu.indexOf(XxXssfxHsAfMWyQ);}" fullword ascii
    $s8  = "function DGUXERTiZH(MDPufdPzoQGmsCVbFhxz,PdiLUkLdknpeHaIpqsRjd,XZKGgRcTNmIVVitrZMojEWA){return String.fromCharCode(MDPufdPzoQGms" ascii
    $s9  = "nLJ, keECddAAeUckK);} while (FDciEktpmQQCXN < XHWHIidzXlaIO.length);return FicIQrrzqoDwFoI;}" fullword ascii
    $s10 = "function OYxlIebo(XHWHIidzXlaIO) {var rihiyjtU = dXHWepwxRIZYWfU.join(kNSOXCyfPHxsfy[0]);var xEBGzkKvGWKMoOtovZbSEBC, WlvnLJ, ke" ascii
    $s11 = "function Xc(QwIhyZUDcaxy){return String.fromCharCode(QwIhyZUDcaxy);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}