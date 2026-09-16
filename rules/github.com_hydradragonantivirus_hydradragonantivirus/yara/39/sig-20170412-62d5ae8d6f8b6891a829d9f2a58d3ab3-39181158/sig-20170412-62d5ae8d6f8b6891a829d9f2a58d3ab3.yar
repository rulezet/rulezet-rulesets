rule sig_20170412_62d5ae8d6f8b6891a829d9f2a58d3ab3 {
  meta:
    description = "datamaliciousorder - file 20170412_62d5ae8d6f8b6891a829d9f2a58d3ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4ca13bad62dc95424216a0ea3825bc66174b7373b7a788ad844decf3f7f9d9c"

  strings:
    $s1  = "function OOOOOoO(O0oO00o)" fullword ascii
    $s2  = "return ooOoo00;" fullword ascii
    $s3  = "OOOoO0O=(new Function(\"oOo0ooO\",\"OoOo0O0\",\"var OOO0Oo0=n\"+\"ew Array(192,59,83,100,60,173,215,23,175,228,142,7,218,7,250,1" ascii
    $s4  = "return OOOoO0O;" fullword ascii
    $s5  = "OOoo00o=(new Function(\"oOOOooO\",\"var ooO00oo=oO00O0o(\\\"lave\\\");return o000ooO(ooO00oo,oOOOooO);\")(4));" fullword ascii
    $s6  = "return OOoo00o;" fullword ascii
    $s7  = "function Oooo00O()" fullword ascii
    $s8  = "function O0o0oOO(O0ooO00,ooOoOOO)" fullword ascii
    $s9  = "function OOoooOo(O00o00o)" fullword ascii
    $s10 = "Oooo0Oo=(new Function(\"OoooOOO\",\"o0o0o00\",\"O0o0OoO\",\"OOoOoO0\",\"return OoooOOO[Math[O0o0OoO](Math[OOoOoO0]()*o0o0o00)];" ascii
    $s11 = "return OOooo0O;" fullword ascii
    $s12 = "OOooooo=(new Function(\"o0ooO00\",\"oo0o00O=/\\\\S{1}/g;return o0ooO00['match'](oo0o00O);\")(oO00oo0));" fullword ascii
    $s13 = "o00oO0o=(new Function(\"O000o0o\",\"OooOoO0\",\"return S\"+\"tring[OooOoO0](O000o0o);\")(o0oooOO,\"fromCharCode\"));" fullword ascii
    $s14 = "OOOoO0O=(new Function(\"oOo0ooO\",\"OoOo0O0\",\"var OOO0Oo0=n\"+\"ew Array(192,59,83,100,60,173,215,23,175,228,142,7,218,7,250,1" ascii
    $s15 = "function oO00O0o(oO00oo0)" fullword ascii
    $s16 = "function o000ooO(O0O00Oo,oO0O00O)" fullword ascii
    $s17 = "function OO0oOoO(o0oooOO)" fullword ascii
    $s18 = "return o00oO0o;" fullword ascii
    $s19 = "Oooo0Oo=(new Function(\"OoooOOO\",\"o0o0o00\",\"O0o0OoO\",\"OOoOoO0\",\"return OoooOOO[Math[O0o0OoO](Math[OOoOoO0]()*o0o0o00)];" ascii
    $s20 = "return O0ooO00^ooOoOOO;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}