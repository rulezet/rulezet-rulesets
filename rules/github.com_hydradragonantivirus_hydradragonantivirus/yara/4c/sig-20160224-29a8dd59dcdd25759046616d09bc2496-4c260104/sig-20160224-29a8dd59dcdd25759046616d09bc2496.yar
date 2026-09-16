rule sig_20160224_29a8dd59dcdd25759046616d09bc2496 {
  meta:
    description = "datamaliciousorder - file 20160224_29a8dd59dcdd25759046616d09bc2496.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcc3e449e2cac6a6bbeb2d5d718923fc2accd012d8798d85fcb0a30c068c7c4e"

  strings:
    $s1 = "    var siegekOC = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "var firebrandaW9 = function(disembarkBYf) {" fullword ascii
    $s3 = "var demonstrableLEN = function() {" fullword ascii
    $s4 = "function btoa(impietyOu6, enraptureKyF, moribundauz, beseechsUN, frontieruiF, modestqtQ, appendETG, avariceL3E) {" fullword ascii
    $s5 = "        return WScript[girdH3B](rhetorica6k);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}