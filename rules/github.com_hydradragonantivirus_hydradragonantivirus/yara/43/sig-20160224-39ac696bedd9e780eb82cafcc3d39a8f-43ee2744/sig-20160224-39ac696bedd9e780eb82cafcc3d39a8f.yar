rule sig_20160224_39ac696bedd9e780eb82cafcc3d39a8f {
  meta:
    description = "datamaliciousorder - file 20160224_39ac696bedd9e780eb82cafcc3d39a8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e475625655efd56e4a0be5de6598ffe0ca9039262bbe439c75fbfa0a854f51a"

  strings:
    $s1 = "    var impietyjPY = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "function btoa(immutablewGq, meritWSJ, readjustmentnZy) {" fullword ascii
    $s3 = "        return WScript[espouseKxy](cleaveZmb);" fullword ascii
    $s4 = "var viscousjXd = function(forebodingSEd) {" fullword ascii
    $s5 = "var querulousB4n = function() {" fullword ascii
    $s6 = "    var toilsWf = String(readjustmentnZy);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}