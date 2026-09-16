rule sig_20160314_49288c16ca67b7235ced522b86b0e57c {
  meta:
    description = "datamaliciousorder - file 20160314_49288c16ca67b7235ced522b86b0e57c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9af9bda07b4cbfaf1aa8b2e134ee722754a3adf7a788d42bfbe225fc4ea74ca7"

  strings:
    $s1 = "while (ZInT.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "return JwktYcIgywxOLYQ + fcjtqClKnuis + kOwSmEOm + vyCPICURVSdL + MgwaUEqW + EeerM + VwD" fullword ascii
    $s3 = "ZInT.open(QGhXixy, lqDPjtdytsZKGkN + CHwc + pCMw + NnYHfFUKpRac + hNDGhHEWFQAQHg + GRrgubSf + nPlyK + exZCWJnRrNM + INl + YAkqPq" ascii
    $s4 = "function oRYKCsKOfDAy(fname)" fullword ascii
    $s5 = "function fdRC(n)" fullword ascii
    $s6 = "SqUEwHoNt + CabREWMLYf, false);" fullword ascii
    $s7 = "var GxQlNJhAkbjKb = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}