rule _20170126_7ad814d6857dbb2cde5879caa2ab7d34_20170126_a117a29fcce5_1626 {
  meta:
    description = "datamaliciousorder - from files 20170126_7ad814d6857dbb2cde5879caa2ab7d34.js, 20170126_a117a29fcce5329bd87149e8ff8d8e82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "741f5f1c651c76fd46642c12422b5d2bce84f42263a01bb4ccb811de304d7fcf"
    hash2       = "38d640838c3806230e54b56c94e9f9922543850a9ddbb4692b0809b1744311af"

  strings:
    $s1  = "return ['', '', '', \"c\\\\\"];" fullword ascii
    $s2  = "return ['', '', '', \"g.\", ''];" fullword ascii
    $s3  = "return ['', '', '', \"Ob\"];" fullword ascii
    $s4  = "return ['', '', '', '', \"te\"];" fullword ascii
    $s5  = "return [\"Ge\", '', '', ''];" fullword ascii
    $s6  = "return [\"TP\", '', ''];" fullword ascii
    $s7  = "return ['', \"XO\", ''];" fullword ascii
    $s8  = "return ['', \"Sc\"];" fullword ascii
    $s9  = "return [\"Ty\", '', ''];" fullword ascii
    $s10 = "return ['', '', \"Sc\"];" fullword ascii
    $s11 = "return ['', '', \"iv\"];" fullword ascii
    $s12 = "return ['', \"te\"];" fullword ascii

  condition:
    (uint16(0) == 0x7566 and (8 of them)
    ) or (all of them)
}