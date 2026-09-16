rule sig_20160315_92d07b76661032951be4f2369bf0205d {
  meta:
    description = "datamaliciousorder - file 20160315_92d07b76661032951be4f2369bf0205d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82d534a87fa990ea90ce90298fabd26c3d384563c9c03dcbc64aa36f35ef5f8d"

  strings:
    $s1 = "while (KjQSgNhYFYb.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function gIzCzEEraz(n){return uGVrvPFsysuIdZR + YNgugdDrL + lAdeSbwft + UdsErm + SnyB + ZxaNZSj;}" fullword ascii
    $s3 = "N + kSrAIYHpReAC + vXWPZyE + bIi + wOytaD + iuluGddh + dyvLQdrEbyhRfz, false);" fullword ascii
    $s4 = "function ZScCaYnBmRrOAHh(fKQxX){WshShell[eseHdpeHz](fKQxX, 0, 0);}" fullword ascii
    $s5 = "var XfHEVieuXasK = new Date();" fullword ascii
    $s6 = "KjQSgNhYFYb[CAkdSuf + FlIZAyk + RhOrgEvHQop](CxBwjVGXORcZRBO + zpJhtRZoy, SbQz + GeNFBCP + AAzPUjCLBCJSW + CaGDcP + RNZbRdOsrv +" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}