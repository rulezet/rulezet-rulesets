rule sig_20170419_fbbda6cb376a740857ed0bec575d930e {
  meta:
    description = "datamaliciousorder - file 20170419_fbbda6cb376a740857ed0bec575d930e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06d09d9a72587b8c34bfa3d6e7fe92382fad49ab9387d714bc138c3f2be83f61"

  strings:
    $s1  = "return oooOoo0;" fullword ascii
    $s2  = "o0oooOO=(new Function(\"o00OOOo\",\"O00O000\",\"var OOooO0O=oo00ooO(O00O000);return OooooOO(OOooO0O,o00OOOo);\")(8,\"evvealla\")" ascii
    $s3  = "oOoO0O0=(new Function(\"Oo0OO0O\",\"oo0o0O0\",\"return Strin\"+\"g[\\\"fromC\\\"+oo0o0O0](Oo0OO0O);\")(OO0o0oo,new Array(1,\"har" ascii
    $s4  = "oooOoo0=(new Function(\"oooOOoO\",\"O0o00O0\",\"var oOo0O0O=n\"+\"ew Array(79,197,18,177,228,18,206,8,17,114,138,67,53,84,242,15" ascii
    $s5  = "function oo00ooO(OOOo00O)" fullword ascii
    $s6  = "function oo0OOOo()" fullword ascii
    $s7  = "return o00OOO0;" fullword ascii
    $s8  = "O0Ooo00=(new Function(\"ooooO00\",\"OO0OooO\",\"return parseI\"+\"\"+\"nt(ooooO00,OO0OooO);\")(oo0OO0o,16));" fullword ascii
    $s9  = "function oooooO0(oo0OO0o)" fullword ascii
    $s10 = "return o0oooOO;" fullword ascii
    $s11 = "return oOoO0O0;" fullword ascii
    $s12 = "o00OOO0=(new Function(\"oo00Oo0\",\"Oo0O00O\",\"O0oooO0\",\"O0OooO0\",\"return oo00Oo0[Math[O0oooO0](Math[O0OooO0]()*Oo0O00O)];" ascii
    $s13 = "function ooO00OO()" fullword ascii
    $s14 = "return ooO0ooo;" fullword ascii
    $s15 = "oooOoo0=(new Function(\"oooOOoO\",\"O0o00O0\",\"var oOo0O0O=n\"+\"ew Array(79,197,18,177,228,18,206,8,17,114,138,67,53,84,242,15" ascii
    $s16 = "function oOOOoOo(OO0o0oo)" fullword ascii
    $s17 = "function OooooOO(oo0O00o,ooooOoO)" fullword ascii
    $s18 = "return O0Ooo00;" fullword ascii
    $s19 = "return o0000Oo^O0OOOo0;" fullword ascii
    $s20 = "O0o000O=(new Function(\"oo00OO0\",\"oOOOoOo\",\"O000o00=/\\\\S{1}/g;return oo00OO0[oOOOoOo](O000o00);\")(OOOo00O,\"match\"));" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}