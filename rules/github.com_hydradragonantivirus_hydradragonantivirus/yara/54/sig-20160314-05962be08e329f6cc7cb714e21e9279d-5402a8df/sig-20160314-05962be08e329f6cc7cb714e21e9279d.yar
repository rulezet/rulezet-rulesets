rule sig_20160314_05962be08e329f6cc7cb714e21e9279d {
  meta:
    description = "datamaliciousorder - file 20160314_05962be08e329f6cc7cb714e21e9279d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dda8f5bedde86adce89c66105798723d2395734bc2e1b37abdaff48fd2267e3"

  strings:
    $s1 = "Vnsbuzifein.open(kjE + HyAEsxLOf, lWVUOh + gnlEYGKwZC + hfvuusUIbwBoF + pGDFEDUFCbm + nCrAO + oVd + WSQytZnzlLZ + ndgIORyZdkcH +" ascii
    $s2 = "while (Vnsbuzifein.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function sGdLlNQg(n)" fullword ascii
    $s4 = " iFGQwVi + XTDwsKXzSU + VZnxhmCMuWZOSBt + qWluZxUrdi + HfZTP + yqNuXf + wDGC, false);" fullword ascii
    $s5 = "return VgMVfbuiLBtn + KRexSlcovy + dughVKLAK + BTxJFkiI + DtqyNiGHGQ + gAfs + LhHragBSRdW + ihrduD" fullword ascii
    $s6 = "function ebvqNa(fname)" fullword ascii
    $s7 = "var UMNIILkPQZRc = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}