rule sig_20160305_15cdaa65b9f1bc06b90f1d937c436208 {
  meta:
    description = "datamaliciousorder - file 20160305_15cdaa65b9f1bc06b90f1d937c436208.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac44938e98f5631c16e7781180eaab3d744b1782804fc66f99cbe32922ca9b4f"

  strings:
    $s1  = "        return WScript[r](a);" fullword ascii
    $s2  = "var vapideja = function(a) {" fullword ascii
    $s3  = "        return false === u.raw || u.utf8decode || t ? v.decode(a) : a;" fullword ascii
    $s4  = "!function(a) {" fullword ascii
    $s5  = "        return a + \"====\".slice(a.length % 4 || 4);" fullword ascii
    $s6  = "    var f = String[\"fro\" + \"m\" + \"Cha\" + \"rCode\"];" fullword ascii
    $s7  = "        a = false === u.raw || u.utf8encode || r ? v.encode(a) : a;" fullword ascii
    $s8  = "        decode: function(a) {" fullword ascii
    $s9  = "    u.atob = u.decode = function(a, t) {" fullword ascii
    $s10 = "var obduratekCa = function() {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}