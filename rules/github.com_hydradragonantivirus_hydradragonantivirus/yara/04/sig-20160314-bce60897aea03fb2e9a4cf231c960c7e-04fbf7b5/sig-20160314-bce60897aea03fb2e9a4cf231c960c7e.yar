rule sig_20160314_bce60897aea03fb2e9a4cf231c960c7e {
  meta:
    description = "datamaliciousorder - file 20160314_bce60897aea03fb2e9a4cf231c960c7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a78ec312b7dc0f84d3d6b36fc158335bfb58c1a9d7ace32b39876fc62882393d"

  strings:
    $s1 = "UpdEgcmSplpsHf.open(NBcPQaDPRZEhu + cJTMAZYmNljzw, tqEq + QeoBLVitJLK + IMXpl + DhITOCqUuPzArK + MQlVmzsaSCEZT + nOkyNjbsFsxazG " ascii
    $s2 = "while (UpdEgcmSplpsHf.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return DNHlsWktsQB + LBSjSAxnJDigiJv + HNnfEnWFhf + OeLivC + iwMRYmNWjkAYGZ" fullword ascii
    $s4 = "hPYVCywIyd + FjZUxRJWbp, false);" fullword ascii
    $s5 = "var znEkcjWFORCH = new Date();" fullword ascii
    $s6 = "function SqJQYEjbwV(n)" fullword ascii
    $s7 = "function lhUbTZ(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}