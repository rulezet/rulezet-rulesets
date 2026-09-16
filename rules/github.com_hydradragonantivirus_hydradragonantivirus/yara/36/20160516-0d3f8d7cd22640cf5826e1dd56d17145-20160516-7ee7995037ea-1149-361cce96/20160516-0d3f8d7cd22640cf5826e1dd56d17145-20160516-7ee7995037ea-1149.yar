rule _20160516_0d3f8d7cd22640cf5826e1dd56d17145_20160516_7ee7995037ea_1149 {
  meta:
    description = "datamaliciousorder - from files 20160516_0d3f8d7cd22640cf5826e1dd56d17145.js, 20160516_7ee7995037ea482250a6bdaf04d774c2.js, 20160516_b2316b61669832c1d877ebd37b58def9.js, 20160516_c1d6d820c59e9210909ac99c90e842ab.js, 20160516_e8c100108f6fa98a9c8bcbb61f0c255d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d5100b8f7f37155118719a0d9fce207507ea283b4551fc38d38de15ab8ad24e"
    hash2       = "682c03ec9899973dc9cbf1ada608456425f8f8f247795f2ae17bb10707ad98e2"
    hash3       = "9c8012e1ebe88df9a85584fa2a8e30407d58a319e64d2264f076319db492c958"
    hash4       = "a1d38cdf06bb3d087dcca05fc4c96b983f8cb50087379f4b4a32b9b582495529"
    hash5       = "86f8055b6fedeabc8a6c231789e8a9466fbf3096446c5246e6d5fd6213035f49"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* f  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* f  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* f  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* f  */(/* f  */\"noitisop\").split(''/* f  */).reverse(/* f  */).join('');" fullword ascii
    $s5  = "for (;place /* f  */;){" fullword ascii
    $s6  = " var place /* f  */ = 3-2;" fullword ascii
    $s7  = "if (place /* f  */ == 1)" fullword ascii
    $s8  = "while (place /* f  */) { " fullword ascii
    $s9  = "place0 /* f  */= true;/* f  */" fullword ascii
    $s10 = "place /* f  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}