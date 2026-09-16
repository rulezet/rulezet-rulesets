rule sig_20160224_259cb8ad1205d969ad7c77795e0d023a {
  meta:
    description = "datamaliciousorder - file 20160224_259cb8ad1205d969ad7c77795e0d023a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebceb9688a1a8027586e713f9cbc766722e32ddff2f2c88de03985725f0157db"

  strings:
    $s1 = "    var consecratekdB = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "var passageQAt = function(frustrateQTb) {" fullword ascii
    $s3 = "        return WScript[testatorfc5](unexceptionableCxA);" fullword ascii
    $s4 = "function btoa(resonantSdr, frontiertu3, conscientiousR9G, bequeathKqu, disaffectedYrU) {" fullword ascii
    $s5 = "var unaffectedwZu = function() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}