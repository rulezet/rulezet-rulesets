rule _20160516_03a73ec8da04a07d2449ec9373ce2b3c_20160516_2d8f4ff53496_1146 {
  meta:
    description = "datamaliciousorder - from files 20160516_03a73ec8da04a07d2449ec9373ce2b3c.js, 20160516_2d8f4ff534962bfd2f4ae3b14a225304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a90fa66d5a2104006c0b119ac41cbebac783fd4cb5c46e8c46b7cdce130bfd07"
    hash2       = "60f4c06d34ab8a921b507ec967727f642945f04bc815d1ed0d9790f6da68ee00"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* D  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* D  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* D  */(/* D  */\"noitisop\").split(''/* D  */).reverse(/* D  */).join('');" fullword ascii
    $s4  = "CONNECTION /* D  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "while (place /* D  */) { " fullword ascii
    $s6  = "place0 /* D  */= true;/* D  */" fullword ascii
    $s7  = "if (place /* D  */ == 1)" fullword ascii
    $s8  = "for (;place /* D  */;){" fullword ascii
    $s9  = " var place /* D  */ = 3-2;" fullword ascii
    $s10 = "place /* D  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}