rule sig_20160225_7c2e0fea8869d0f252cb5b1dacea1538 {
  meta:
    description = "datamaliciousorder - file 20160225_7c2e0fea8869d0f252cb5b1dacea1538.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f92913881391fcd86a19e01f26030dae476e930ff6f6ef526f7d3bfed377d207"

  strings:
    $s1 = "    var modestgJm = String[\"sdfadfasdffromChar\".slice(10) + \"Codedsfadsfasdg\".slice(0, 4)];" fullword ascii
    $s2 = "            bemuseYD0.open(nattyPnc([ 203, 53, 193 ]), irresolutemP0, false);" fullword ascii
    $s3 = "        return WScript[denseFep](perfidiousbCC);" fullword ascii
    $s4 = "var nattyPnc = function(filchwHQ) {" fullword ascii
    $s5 = "function btoa(irksomensw, rococoHVB, deignolK, conceitVnI, functionaryIQO, objectivevVA) {" fullword ascii
    $s6 = "var ambrosiaidB = function() {" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}