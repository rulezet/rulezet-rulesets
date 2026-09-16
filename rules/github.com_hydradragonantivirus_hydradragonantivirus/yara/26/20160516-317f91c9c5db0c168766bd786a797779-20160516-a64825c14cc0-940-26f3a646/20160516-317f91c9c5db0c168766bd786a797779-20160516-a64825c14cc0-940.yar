rule _20160516_317f91c9c5db0c168766bd786a797779_20160516_a64825c14cc0_940 {
  meta:
    description = "datamaliciousorder - from files 20160516_317f91c9c5db0c168766bd786a797779.js, 20160516_a64825c14cc08b736cbb5e64e42fcb08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f1edb7852656e419489113c21c45b5957b7fe18cc36b2d1305c67dd5d93f51c"
    hash2       = "5f6179df5a15c7c3f552816c360c864917ccccbef2d16aeaa007ede2982d9aa2"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* YL  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* YL  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* YL  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* YL  */(/* YL  */\"noitisop\").split(''/* YL  */).reverse(/* YL  */).join('');" fullword ascii
    $s5  = "for (;place /* YL  */;){" fullword ascii
    $s6  = " var place /* YL  */ = 3-2;" fullword ascii
    $s7  = "place0 /* YL  */= true;/* YL  */" fullword ascii
    $s8  = "while (place /* YL  */) { " fullword ascii
    $s9  = "if (place /* YL  */ == 1)" fullword ascii
    $s10 = "place /* YL  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}