rule sig_20160314_38adc6975bf5dd011d113170964dec3a {
  meta:
    description = "datamaliciousorder - file 20160314_38adc6975bf5dd011d113170964dec3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a906985395a939f37b1dcb311fcfa35f49fdea6b4ba0a36f2ef24ded4c82295"

  strings:
    $s1  = "WshShell = WScript.CreateObject(Tlsgg + FAkY + QgjoMtM + kLmCLhXo + ZbtfTTIW + JChfyotnQVgkD);" fullword ascii
    $s2  = "WshShell[avdJWYmvQIA + DhOW + KZytyxZ](fname, 0, 0);" fullword ascii
    $s3  = "while (sKmWo.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s4  = "KR + Tom + tyuzSAzCve + brwGSjdvZJ + jiIRQdh + mxgqathmXb, false);" fullword ascii
    $s5  = "return Kpc + pTxfitLfOcXkHt + hEJXmm + IitrAjnTASO + VoevagzyOCv + EYvjBzMffS + BWtlmBOelnLN + nmuXoMhR" fullword ascii
    $s6  = "sKmWo.open(wXexKVo, kMBcBtYmDDdIi + qSBMyNLoEdAr + BjgEfBcXMglEm + iZyQPMuh + ezAfQxwOEZwdI + oBmWHiN + XIrlZTfpMICb + fVCTuEca " ascii
    $s7  = "function wWOSXrMqgXMJ(n)" fullword ascii
    $s8  = "+ VNCHooAKqpuXIcv + OaNlNcYVULb + Dobe + vepVg + AbcHnnPZDgu + bzuoUfNOR + hCAnNzAUMGCd + ZIDtHbep + UFKRyOYrYiwsD + IfyQbNkijdp" ascii
    $s9  = "var Dobe = \"tte\";" fullword ascii
    $s10 = "var FAkY = \"cri\";" fullword ascii
    $s11 = "function DdcwMjXQQ(fname)" fullword ascii
    $s12 = "var XgvYP = new Date();" fullword ascii
    $s13 = "var DhOW = \"u\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}