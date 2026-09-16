rule _20160516_180c9cf0e426a12475f6cc0eb7fdf2a8_20160516_75fdc80b2c15_1151 {
  meta:
    description = "datamaliciousorder - from files 20160516_180c9cf0e426a12475f6cc0eb7fdf2a8.js, 20160516_75fdc80b2c1554aa07e8e2abbc2cf71e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "648ae8625f1d421f718154059bc486442425f3caaf14d4197085d59add8433a8"
    hash2       = "70afdd2d710bb8db0444c82e190c5079edf4506b8537454ff3fc9619643ed8a4"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* F  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* F  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* F  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* F  */(/* F  */\"noitisop\").split(''/* F  */).reverse(/* F  */).join('');" fullword ascii
    $s5  = " var place /* F  */ = 3-2;" fullword ascii
    $s6  = "if (place /* F  */ == 1)" fullword ascii
    $s7  = "place0 /* F  */= true;/* F  */" fullword ascii
    $s8  = "for (;place /* F  */;){" fullword ascii
    $s9  = "while (place /* F  */) { " fullword ascii
    $s10 = "place /* F  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}