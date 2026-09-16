rule sig_20160305_4ae889011163d985f6a2ba26b3e8c37b {
  meta:
    description = "datamaliciousorder - file 20160305_4ae889011163d985f6a2ba26b3e8c37b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "369a2597f221b85420f6335baed35871ce218e1562bced08d3d8fae2ac0c7630"

  strings:
    $s1 = "        return WScript[a](r);" fullword ascii
    $s2 = "var daisvvN = function(r) {" fullword ascii
    $s3 = "        return false === u.raw || u.utf8decode || e ? n.decode(r) : r;" fullword ascii
    $s4 = "var rejoinderf1i = function() {" fullword ascii
    $s5 = "        return r + \"====\".slice(r.length % 4 || 4);" fullword ascii
    $s6 = "    var f = String[\"f\" + \"r\" + \"o\" + \"mCharCode\"];" fullword ascii
    $s7 = "        r = false === u.raw || u.utf8encode || a ? n.encode(r) : r;" fullword ascii
    $s8 = "    u.atob = u.decode = function(r, e) {" fullword ascii
    $s9 = "        decode: function(r) {" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    all of them
}