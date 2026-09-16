rule sig_20151229_6395942fee4da6f18df8ba0e8b9f61a2 {
  meta:
    description = "datamaliciousorder - file 20151229_6395942fee4da6f18df8ba0e8b9f61a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "780476c45e3bdf4ed18867fb10190191dc9d61aa5734e27601dc1ed782254141"

  strings:
    $s1 = "print (jyqqtvzpa);" fullword ascii
    $s2 = "//}else{" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}