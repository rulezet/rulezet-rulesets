rule _20160516_555a4daece308d316d1b72d8146d5ebf_20160516_57591029e483_1163 {
  meta:
    description = "datamaliciousorder - from files 20160516_555a4daece308d316d1b72d8146d5ebf.js, 20160516_57591029e483d2555d69f97231b7b7f2.js, 20160516_f85ac230652e4a03ae6545b34128bd43.js, 20160516_f8f5ebb076ef6f57c5f4134741dddcbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85bcdee6bdd679cec0e8020c818c59dfabc6f5e7251e1cbb444139b55b538a54"
    hash2       = "9ee8b124702fb5ea76d2fa2b1eb28654a738623606a177babb20a1bd41a07651"
    hash3       = "28e3903598052a8c9f013b824bddd96153634f237be4cdd8cd6a6c537d43f7ae"
    hash4       = "e9ba204a8942dc7e319a11a9822d76f6b9fe26fc7cf4698c0ac9a28896637df9"

  strings:
    $s1  = "var VALIGN1 = function VALIGN() {return stepy[VALIGN0]((\"fdasfadsfaszxvc\", CONNECTION /* u  */)+\".Shell\");}(), aaa0 = 11;" fullword ascii
    $s2  = "place /* u  */ = 5316 - 5314;" fullword ascii
    $s3  = "CONNECTION /* u  */ = \"W\"+\"S\"+\"c\"+\"ript\";" fullword ascii
    $s4  = "Turkey = /* u  */(/* u  */\"noitisop\").split(''/* u  */).reverse(/* u  */).join('');" fullword ascii
    $s5  = "if (place /* u  */ == 1)" fullword ascii
    $s6  = "for (;place /* u  */;){" fullword ascii
    $s7  = "place0 /* u  */= true;/* u  */" fullword ascii
    $s8  = " var place /* u  */ = 3-2;" fullword ascii
    $s9  = "while (place /* u  */) { " fullword ascii
    $s10 = "place /* u  */ = catchKeyCode;" fullword ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}