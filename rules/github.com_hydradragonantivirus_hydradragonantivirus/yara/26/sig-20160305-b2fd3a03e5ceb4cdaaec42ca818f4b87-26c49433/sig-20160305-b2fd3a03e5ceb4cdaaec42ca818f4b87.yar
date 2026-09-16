rule sig_20160305_b2fd3a03e5ceb4cdaaec42ca818f4b87 {
  meta:
    description = "datamaliciousorder - file 20160305_b2fd3a03e5ceb4cdaaec42ca818f4b87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2ea66a52fde43a621dc10d1c8ea207aef25c699e34d38b5bc4b20fbf28678d1"

  strings:
    $s1  = "var badinageTkb = function(a) {" fullword ascii
    $s2  = "        return WScript[r](a);" fullword ascii
    $s3  = "!function(a) {" fullword ascii
    $s4  = "        return false === u.raw || u.utf8decode || n ? i.decode(a) : a;" fullword ascii
    $s5  = "        i.open(badinageTkb([ 137, 214, 71 ]), g, false);" fullword ascii
    $s6  = "var exaltOs5 = function() {" fullword ascii
    $s7  = "        return a + \"====\".slice(a.length % 4 || 4);" fullword ascii
    $s8  = "    var u = String[\"fr\" + \"o\" + \"mCh\" + \"arCode\"];" fullword ascii
    $s9  = "        a = false === u.raw || u.utf8encode || r ? i.encode(a) : a;" fullword ascii
    $s10 = "        decode: function(a) {" fullword ascii
    $s11 = "    u.atob = u.decode = function(a, n) {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    8 of them
}