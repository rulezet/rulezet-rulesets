rule sig_20160301_c6adc6ba8700638edf380af1f65d2078 {
  meta:
    description = "datamaliciousorder - file 20160301_c6adc6ba8700638edf380af1f65d2078.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44d05c4fa04ff97aa1362a99ef2c6fa7a7ff73e55d3acdb6622b0655a6968e32"

  strings:
    $s1 = "portionExpert = territoryExpertise[(\"role\", \"tribune\", \"ExpandEnvironmentStrings\")]((\"academy\", \"cardinal\", \"public\"" ascii
    $s2 = "while(perspectiveExport[(\"readystate\")] < (186, 2) * (48 - 46)) {" fullword ascii
    $s3 = "portionExpert = territoryExpertise[(\"role\", \"tribune\", \"ExpandEnvironmentStrings\")]((\"academy\", \"cardinal\", \"public\"" ascii
    $s4 = "numerationIllustration = (((132, 3354) / (71, 26)), this);" fullword ascii
    $s5 = "} catch(dictionGroup) {};" fullword ascii

  condition:
    uint16(0) == 0x756e and
    all of them
}