rule _20160516_a328906a3bf97bd38f2db07fd075852e_20160516_b5c0ef337742_1176 {
  meta:
    description = "datamaliciousorder - from files 20160516_a328906a3bf97bd38f2db07fd075852e.js, 20160516_b5c0ef33774275d4e27ece805b4ef268.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3a2d203fdc71bd35dc0b65efa4a15f9fef7830badff666e35a3cc58a5cbac25"
    hash2       = "87847c97fc3fef4fb55cdaa59786bdc46603c54d433dde89159e057935bf6f37"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* e  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* e  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* e  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* e  */(/* e  */\"noitisop\").split(''/* e  */).reverse(/* e  */).join('');" fullword ascii
    $s5  = "for (;place /* e  */;){" fullword ascii
    $s6  = "while (place /* e  */) { " fullword ascii
    $s7  = "place0 /* e  */= true;/* e  */" fullword ascii
    $s8  = " var place /* e  */ = 3-2;" fullword ascii
    $s9  = "if (place /* e  */ == 1)" fullword ascii
    $s10 = "place /* e  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}