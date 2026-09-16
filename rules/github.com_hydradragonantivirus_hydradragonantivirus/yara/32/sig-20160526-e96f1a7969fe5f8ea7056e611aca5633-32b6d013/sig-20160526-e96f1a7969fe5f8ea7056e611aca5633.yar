rule sig_20160526_e96f1a7969fe5f8ea7056e611aca5633 {
  meta:
    description = "datamaliciousorder - file 20160526_e96f1a7969fe5f8ea7056e611aca5633.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "729bcb51b86342593225d1a36059b5a8149d43e45fe4dec707bb5c0929cd0d18"

  strings:
    $s1  = "(Math.cos(913), 2) - 1))-205)) kaGEoxizpwhCYHI += cSGhEYrpqq(fQwnGQKL, CwDGBrTtonDGWHLHoAECc);else kaGEoxizpwhCYHI += XgRfjRct(f" ascii
    $s2  = "12), 2) - 1))-310)) kaGEoxizpwhCYHI += p(fQwnGQKL);else if (hESqbYZb == (269 + Math.round((Math.pow(Math.sin(913), 2) + Math.pow" ascii
    $s3  = "function rjISD(SsNMKwBsQlFAF) {var ZrRYQ = uCAuMFWDAkFTHJFNheFGkCbk.join(ZRTnVPliTmWxz[0]);var fQwnGQKL, CwDGBrTtonDGWHLHoAECc, " ascii
    $s4  = "function LvGHzztLCdlH(hdsnE,mXlOkWE){return hdsnE.charAt(mXlOkWE);}" fullword ascii
    $s5  = "function GfqztYOPItCiLDvSN(tWzfdlLTsa,hpyMPUuYAueyTlRo){return tWzfdlLTsa.indexOf(hpyMPUuYAueyTlRo);}" fullword ascii
    $s6  = "function cSGhEYrpqq(wntjtpDjyuAMzhaB,ydIWyA){return String.fromCharCode(wntjtpDjyuAMzhaB,ydIWyA);}" fullword ascii
    $s7  = "QwnGQKL, CwDGBrTtonDGWHLHoAECc, lnPjKMRHDlmitPNiR);} while (AxGMaePxSQtxleDyleYi < SsNMKwBsQlFAF.length);return kaGEoxizpwhCYHI;" ascii
    $s8  = "function XgRfjRct(Ibuqbb,JmvxsD,KGTHBSlak){return String.fromCharCode(Ibuqbb,JmvxsD,KGTHBSlak);}" fullword ascii
    $s9  = "function p(UMryCoS){return String.fromCharCode(UMryCoS);}" fullword ascii
    $s10 = "function rjISD(SsNMKwBsQlFAF) {var ZrRYQ = uCAuMFWDAkFTHJFNheFGkCbk.join(ZRTnVPliTmWxz[0]);var fQwnGQKL, CwDGBrTtonDGWHLHoAECc, " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}