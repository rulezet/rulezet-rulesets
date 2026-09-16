rule _20160516_78df5e154fd1f84102dc033d3c9ff271_20160516_f73a925101c8_1172 {
  meta:
    description = "datamaliciousorder - from files 20160516_78df5e154fd1f84102dc033d3c9ff271.js, 20160516_f73a925101c89ad4f7019322a1ee23c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a28df79d5c375a80a7b8744ea26e8319a11e87cdbb891058ef34ed65609a6ef1"
    hash2       = "65e917c5b75c5bcc0933c954dcb45674510d4072abbccd60bc2ba0c4bfb25e96"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* S  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* S  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* S  */(/* S  */\"noitisop\").split(''/* S  */).reverse(/* S  */).join('');" fullword ascii
    $s4  = "CONNECTION /* S  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "place0 /* S  */= true;/* S  */" fullword ascii
    $s6  = " var place /* S  */ = 3-2;" fullword ascii
    $s7  = "if (place /* S  */ == 1)" fullword ascii
    $s8  = "for (;place /* S  */;){" fullword ascii
    $s9  = "while (place /* S  */) { " fullword ascii
    $s10 = "place /* S  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}