rule sig_20160305_c6d83bfc1b96a3910b44f8a425af3b9c {
  meta:
    description = "datamaliciousorder - file 20160305_c6d83bfc1b96a3910b44f8a425af3b9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d5a528776c98f4d69ff547a88bebed7e64d4e243ce797e79f7518d5c38a73f4"

  strings:
    $s1 = "var postulateDTo = function() {" fullword ascii
    $s2 = "        return WScript[a](r);" fullword ascii
    $s3 = "        return false === v.raw || v.utf8decode || e ? c.decode(r) : r;" fullword ascii
    $s4 = "        return r + \"====\".slice(r.length % 4 || 4);" fullword ascii
    $s5 = "    var s = String[\"f\" + \"ro\" + \"m\" + \"C\" + \"h\" + \"arCode\"];" fullword ascii
    $s6 = "        r = false === v.raw || v.utf8encode || a ? c.encode(r) : r;" fullword ascii
    $s7 = "        decode: function(r) {" fullword ascii
    $s8 = "    v.atob = v.decode = function(r, e) {" fullword ascii
    $s9 = "var captiousgAc = function(r) {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}