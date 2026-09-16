rule sig_20160301_a371934d52206a9a461da9a8121ca8b8 {
  meta:
    description = "datamaliciousorder - file 20160301_a371934d52206a9a461da9a8121ca8b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b0164c629c6867407a711aca984da0023e7a054b7a8aff39764419c7b2d9f81"

  strings:
    $s1 = "}, \"%TEMP%/\")) + (\"object\", \"collection\", \"resolution\", \"anonymous\", \"imitationModern\") + (\"studio\", \"appeal\", " ascii
    $s2 = "while(lecturePolar[(\"readystate\")] < (([!+[] + !+[]]) * ([!+[] + !+[]]))) {" fullword ascii
    $s3 = "laboratoryPortal = (((29 | 43) * (32 / 8) + (5 + 11)), this);" fullword ascii
    $s4 = "boardConductor = regionPassion[(\"tract\", \"social\", \"academic\", \"ExpandEnvironmentStrings\")]((\"handicap\", function Stri" ascii
    $s5 = "boardConductor = regionPassion[(\"tract\", \"social\", \"academic\", \"ExpandEnvironmentStrings\")]((\"handicap\", function Stri" ascii
    $s6 = "} catch(bananaMajor) {};" fullword ascii

  condition:
    uint16(0) == 0x616c and
    all of them
}