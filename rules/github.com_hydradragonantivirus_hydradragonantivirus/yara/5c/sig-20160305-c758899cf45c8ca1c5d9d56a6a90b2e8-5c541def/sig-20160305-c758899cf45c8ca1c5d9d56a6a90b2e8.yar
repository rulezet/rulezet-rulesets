rule sig_20160305_c758899cf45c8ca1c5d9d56a6a90b2e8 {
  meta:
    description = "datamaliciousorder - file 20160305_c758899cf45c8ca1c5d9d56a6a90b2e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b95ead1200ab60b626429e28d663ccf676d6537df145ad7fd0057df892cdff17"

  strings:
    $s1  = "        return WScript[r](a);" fullword ascii
    $s2  = "var pathologicalpUq = function(a) {" fullword ascii
    $s3  = "!function(a) {" fullword ascii
    $s4  = "        return false === p.raw || p.utf8decode || t ? n.decode(a) : a;" fullword ascii
    $s5  = "        return a + \"====\".slice(a.length % 4 || 4);" fullword ascii
    $s6  = "    var e = String[\"fr\" + \"om\" + \"C\" + \"harCode\"];" fullword ascii
    $s7  = "        a = false === p.raw || p.utf8encode || r ? n.encode(a) : a;" fullword ascii
    $s8  = "        decode: function(a) {" fullword ascii
    $s9  = "    p.atob = p.decode = function(a, t) {" fullword ascii
    $s10 = "var carrionY8h = function() {" fullword ascii
    $s11 = "        c.open(pathologicalpUq([ 112, 67, 27 ]), g, false);" fullword ascii

  condition:
    uint16(0) == 0x6621 and
    8 of them
}