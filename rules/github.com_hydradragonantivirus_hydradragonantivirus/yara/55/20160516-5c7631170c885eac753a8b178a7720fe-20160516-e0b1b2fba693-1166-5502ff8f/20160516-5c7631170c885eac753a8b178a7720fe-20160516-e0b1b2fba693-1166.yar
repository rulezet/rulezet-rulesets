rule _20160516_5c7631170c885eac753a8b178a7720fe_20160516_e0b1b2fba693_1166 {
  meta:
    description = "datamaliciousorder - from files 20160516_5c7631170c885eac753a8b178a7720fe.js, 20160516_e0b1b2fba6930016a5fe04bc0204a335.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd5eb8761b1b60129187c4d73a8008095e4f0efb85700f86fbb7dfbfba9a7471"
    hash2       = "aea1465c623c8c6d36a7c8bfe6fa8b7b1a09aba19fda8484c28e088402f5a10c"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* g  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* g  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* g  */(/* g  */\"noitisop\").split(''/* g  */).reverse(/* g  */).join('');" fullword ascii
    $s4  = "CONNECTION /* g  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "if (place /* g  */ == 1)" fullword ascii
    $s6  = "while (place /* g  */) { " fullword ascii
    $s7  = "for (;place /* g  */;){" fullword ascii
    $s8  = "place0 /* g  */= true;/* g  */" fullword ascii
    $s9  = " var place /* g  */ = 3-2;" fullword ascii
    $s10 = "place /* g  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}