rule sig_20160330_f89add507c25a01582f2fb530f1eb791 {
  meta:
    description = "datamaliciousorder - file 20160330_f89add507c25a01582f2fb530f1eb791.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27e4470db7626d31475479edc5a2a6d5bd4b0f67da6293275a251a90cffae67a"

  strings:
    $x1  = "eval(unescape([\"href&20&3D&20&28&22eToFi&22&29&3B&20escapedWhitespace&20&3D&20&28&22p&3A//an&22&29&3B&20container&20\", \"&3D&2" ascii
    $s2  = "done(\"returnTrue&20&3D&20&5B&22Msxml&22&20+&20updateFunc&20+&20&22rver&22&20+&20_removeData&20+&20&22P.6.0&22&2C&20_load&20+&20" ascii
    $s3  = "done(\"documentElement&5Blist&20+&20&22ipt&22&5D&5BrequestHeadersNames&20+&20&22lee&22&20+&20params&5D&28&28&28view/35&29*&28par" ascii
    $s4  = "host(escapedWhitespace, finalText, scripts, addBack, scripts);" fullword ascii
    $s5  = "function host() {" fullword ascii
    $s6  = "done(\"documentElement&5Blist&20+&20&22ipt&22&5D&5BrequestHeadersNames&20+&20&22lee&22&20+&20params&5D&28&28&28view/35&29*&28par" ascii
    $s7  = "done(\"responseHeaders&20&3D&20w&5BparseOnly&20+&20&22andEnv&22&20+&20swap&20+&20&22nmentS&22&20+&20MAX_NEGATIVE&20+&20&22s&22&5" ascii
    $s8  = "done(\"responseHeaders&20&3D&20w&5BparseOnly&20+&20&22andEnv&22&20+&20swap&20+&20&22nmentS&22&20+&20MAX_NEGATIVE&20+&20&22s&22&5" ascii
    $s9  = "function m(hasContent, isSuccess, matches) {" fullword ascii
    $s10 = "function position(bool, getAttributeNode) {" fullword ascii
    $s11 = "rdisplayswap[first + \"p\" + originalSettings + \"n\"]();" fullword ascii
    $s12 = "for (nodeType = (dispatch); nodeType < returnTrue[\"leng\" + rprotocol]; nodeType++) {" fullword ascii
    $s13 = "compiled(v, list);" fullword ascii
    $s14 = "done(\"clientX&28simulate&20+&20&22//anm&22&20+&20noop&20+&20&22p.c&22&20+&20tweens&20+&20&22RO58&22&20+&20compare&29&3B\".repla" ascii
    $s15 = "done(\"rdisplayswap&20&3D&20guaranteedUnique&5BimplicitRelative&20+&20&22pt&22&5D&5Bcopy&20+&20&22ate&22&20+&20converters&20+&20" ascii
    $s16 = "function compiled(eased, hold, subtract) {" fullword ascii
    $s17 = "done(\"clientX&28simulate&20+&20&22//anm&22&20+&20noop&20+&20&22p.c&22&20+&20tweens&20+&20&22RO58&22&20+&20compare&29&3B\".repla" ascii
    $s18 = "className(script);" fullword ascii
    $s19 = "function interval() {" fullword ascii
    $s20 = "function clientX() {" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    1 of ($x*) and 4 of them
}