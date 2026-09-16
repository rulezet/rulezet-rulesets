rule _20160516_2d2ecd8f62559784964fe359132b9883_20160516_93f6ca8ca8e1_1156 {
  meta:
    description = "datamaliciousorder - from files 20160516_2d2ecd8f62559784964fe359132b9883.js, 20160516_93f6ca8ca8e1d30627041f706688dd3b.js, 20160516_e6a18384064156e89cd9479c61bd4791.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "699125cd7b454aef3ade127feed7aeef790f03a8e36f6bb7f0419a2ef2bace26"
    hash2       = "af3693fa13639c6406440c4a23504890349c901492d3bb1d3b22a8a5d0ce9c1e"
    hash3       = "157f8a577394db1ea30d5f4d9441ee916ebec3f03078bec81b308eac33cdaf7e"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* n  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* n  */ = 5316 - 5314;" fullword ascii
    $s3  = "Turkey = /* n  */(/* n  */\"noitisop\").split(''/* n  */).reverse(/* n  */).join('');" fullword ascii
    $s4  = "CONNECTION /* n  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s5  = "while (place /* n  */) { " fullword ascii
    $s6  = "for (;place /* n  */;){" fullword ascii
    $s7  = "place0 /* n  */= true;/* n  */" fullword ascii
    $s8  = " var place /* n  */ = 3-2;" fullword ascii
    $s9  = "if (place /* n  */ == 1)" fullword ascii
    $s10 = "place /* n  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}