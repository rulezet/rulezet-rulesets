rule sig_20170327_e7affff8c47cf9e2d0205faa46106da8 {
  meta:
    description = "datamaliciousorder - file 20170327_e7affff8c47cf9e2d0205faa46106da8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59050c9eb18d1aad5b207e68e075ddb3d00edff894a90d6b4eded43f98905010"

  strings:
    $s1 = "function o000o0()" fullword ascii
    $s2 = "function OOOo0O()" fullword ascii
    $s3 = "return Oooo0O;" fullword ascii
    $s4 = "return OOO0O0;" fullword ascii
    $s5 = "return Oooooo;" fullword ascii
    $s6 = "function ooo00O(OO0OOO)" fullword ascii
    $s7 = "Oooo0O=(new Function(\"Oooo00\",\"var ooo0Oo=new Array(92,21,16,66,33,150,6,199),oOOo0o=Oooo00.match(/\\\\S{2}/g),o00Ooo=\\\"" ascii
    $s8 = "Oooo0O=(new Function(\"Oooo00\",\"var ooo0Oo=new Array(92,21,16,66,33,150,6,199),oOOo0o=Oooo00.match(/\\\\S{2}/g),o00Ooo=\\\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}