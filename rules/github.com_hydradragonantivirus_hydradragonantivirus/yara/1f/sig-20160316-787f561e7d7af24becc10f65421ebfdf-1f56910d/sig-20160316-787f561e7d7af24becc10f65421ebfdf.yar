rule sig_20160316_787f561e7d7af24becc10f65421ebfdf {
  meta:
    description = "datamaliciousorder - file 20160316_787f561e7d7af24becc10f65421ebfdf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e60df3c953cf613960a7d0cac90a142eb7629448bb430398fc23deffa0aead3"

  strings:
    $s1 = "while (SYPrTe[KcfMtSxolZ + UvPOA + PTKR + yTF + uLymnFweqZ] < 4 ) {WScript[HBATGrfVq + cILXN + UAWNJLJ](1000)};" fullword ascii
    $s2 = "SYPrTe[xgvJ + MDZyxG + UGrj](rNznRCDBoKh, eHRD + TmOYE + TMnUeiZI + GnjJlDfVLZWd + JHFxutJxpBWkKjN + GKx0 + ZmKl + JnlFOawokLGOh" ascii
    $s3 = "function BaY(LvV){muZfHibZYe[juR + TucSgH](LvV, 0, 0);}" fullword ascii
    $s4 = "function LWyoddfpkuWktdJ(n){return XKWPlNyQXoMZys + fiUKoYBoQTS + HFSc + brWqwFySV + SuvhSemx + gNtwfdxzSpK + AJZ;}" fullword ascii
    $s5 = " + uRuvwsWYN + rwdyhCYnPIDLc + aaCONXXyDwj + FMsiygIWRvg + zLYGlRKBhMxMn, false);" fullword ascii
    $s6 = "var qDMIULfvnsMQri = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}