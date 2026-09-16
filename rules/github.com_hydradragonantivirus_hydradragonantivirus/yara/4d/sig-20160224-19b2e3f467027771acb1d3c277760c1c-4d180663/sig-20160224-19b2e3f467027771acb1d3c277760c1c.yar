rule sig_20160224_19b2e3f467027771acb1d3c277760c1c {
  meta:
    description = "datamaliciousorder - file 20160224_19b2e3f467027771acb1d3c277760c1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68a4031ec7789f9d68d6851e9ba39f8ff80b4208d8b91b100f296ba9668164e5"

  strings:
    $s1 = "    var batefij = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "        return WScript[gravitymAw](citeaRy);" fullword ascii
    $s3 = "function btoa(deposeljw, recoveringOmM, vatjwS) {" fullword ascii
    $s4 = "var peongK8 = function() {" fullword ascii
    $s5 = "var stintkOb = function(languidVuo) {" fullword ascii
    $s6 = "    return threadbarey9F;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}