rule sig_20160315_f257e8a67c29cea5422bdc7954526037 {
  meta:
    description = "datamaliciousorder - file 20160315_f257e8a67c29cea5422bdc7954526037.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "196a912454e7d51a3143d5a7fb8666446bc759197f51e9ab316ef4497b3a1170"

  strings:
    $s1 = "while (AVYeRgMjGUr.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function xWEYIzgraij(pQpqfryJhL){WshShell[DpRPcfp](pQpqfryJhL, 0, 0);}" fullword ascii
    $s3 = "AVYeRgMjGUr[nCFs + wvQ](BCdkVGWf, WMJVazv + MGEdF + nDIEScclfZQDA + WClmIhsijmLwAnj + xUBgAOKlWwPQAra + toNT + guslu + bUSCHt + " ascii
    $s4 = "xeJmd + QzALmP + jcuGVwi + JLgHrCJHYo, false);" fullword ascii
    $s5 = "function ndKhxAIV(n){return oXTcVTjsFSve + KfuEESDDpcT + KzPIGGUieFWEHA + qKAe + ITIwOzNbuWW + jndk + vpElikJm;}" fullword ascii
    $s6 = "var utTBugkhF = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}