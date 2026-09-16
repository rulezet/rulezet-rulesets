rule sig_20160301_a25666ed535d8756bbbc8ed90e6938e2 {
  meta:
    description = "datamaliciousorder - file 20160301_a25666ed535d8756bbbc8ed90e6938e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2735a2fb67378ab28813ededcb01a75cea6b0419727af0478727a1d3c7b03aa6"

  strings:
    $s1 = "examineRegularity[(\"s\\u0075\" + \"\\u0070\\u0065rm\" + \"\\u0061n\", function String.prototype.showRegenerate() {" fullword ascii
    $s2 = "while (examineRegularity[(\"la\\u0064\" + \"\\u0079\", \"r\" + \"\\u0065a\\u0064y\\u0073\\u0074\" + \"a\" + \"\\u0074e\")] < (12" ascii
    $s3 = "contactInstance = ((0 | 1), this);" fullword ascii
    $s4 = "} catch (variantComponent) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}