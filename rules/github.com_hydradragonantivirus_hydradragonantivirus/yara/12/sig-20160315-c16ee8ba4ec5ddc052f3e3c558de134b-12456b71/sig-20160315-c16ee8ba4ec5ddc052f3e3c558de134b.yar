rule sig_20160315_c16ee8ba4ec5ddc052f3e3c558de134b {
  meta:
    description = "datamaliciousorder - file 20160315_c16ee8ba4ec5ddc052f3e3c558de134b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1012c44f79c4882cd53499f8f018f007944a7d694b1752713e2a2aefacaf91ab"

  strings:
    $s1 = "while (luUWKzMtbG.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function LKmYeGinQA(mtYeyOvKyMWxb){WshShell[wriyJhicrEETHS + wmXcAKiiFyKN](mtYeyOvKyMWxb, 0, 0);}" fullword ascii
    $s3 = "function XShrHljGvKliife(n){return ZLDeGFMPea + qSqhdo + SdQOMeRyH + GAYMqrfu + cyc + RMVxKiHxw + kVnR + VURsCnVr + ZIgSFAt + Gd" ascii
    $s4 = "+ SKURxZ + wPbkvxlzImR + KOZdnWNDCZNek, false);" fullword ascii
    $s5 = "function XShrHljGvKliife(n){return ZLDeGFMPea + qSqhdo + SdQOMeRyH + GAYMqrfu + cyc + RMVxKiHxw + kVnR + VURsCnVr + ZIgSFAt + Gd" ascii
    $s6 = "luUWKzMtbG[xBlXwlH + tMjJy + zCOQuafgsMI](xJAFn, Pdz + occNEmqUkDIFAp + VadYtbb + nSaytetKzA + JLDo + BSyXuskRePp + zNCqCibXsb +" ascii
    $s7 = "var VmeVw = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}