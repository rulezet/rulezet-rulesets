rule sig_20160301_ec786b40358f94f5c5bdc1cdcc3a0aed {
  meta:
    description = "datamaliciousorder - file 20160301_ec786b40358f94f5c5bdc1cdcc3a0aed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9922ee94d3fcf1a40759362a4f8f2d04c7f9ea2cf97326ce3acdf0dd22b4abb9"

  strings:
    $s1 = "while(examinationMandate[(\"or\" + \"\\u0067an\" + \"i\" + \"\\u0073m\", function String.prototype.prologueTampon() {" fullword ascii
    $s2 = "instrumentPredicate = (((([+!+[]])) * (1 + 0)), this);" fullword ascii
    $s3 = "} catch(divisionClan) {};" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    all of them
}