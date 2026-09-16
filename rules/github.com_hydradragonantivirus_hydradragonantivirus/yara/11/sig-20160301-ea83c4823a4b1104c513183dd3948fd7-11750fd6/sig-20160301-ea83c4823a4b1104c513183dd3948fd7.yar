rule sig_20160301_ea83c4823a4b1104c513183dd3948fd7 {
  meta:
    description = "datamaliciousorder - file 20160301_ea83c4823a4b1104c513183dd3948fd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e3740dce3027d7d34094cfe25d22a23bc484a95adf87bf1b6021d539280b7ba"

  strings:
    $x1 = "boardHotel = combineFortune[(\"portal\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"offset\", \"instruction\", \"predica" ascii
    $s2 = "boardHotel = combineFortune[(\"portal\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) + (\"offset\", \"instruction\", \"predica" ascii
    $s3 = "while (boardTampon[(\"sexual\", \"director\", \"readystate\")] < (([!+[] + !+[]]) * ([!+[] + !+[]]))) {" fullword ascii
    $s4 = "voltDog = ((([!+[] + !+[]]) * ([!+[] + !+[] + !+[]]) * ([!+[] + !+[]]) * ([!+[] + !+[]]) * ([!+[] + !+[]])), this);" fullword ascii
    $s5 = "boardTampon[(\"liberal\", \"instrument\", \"department\", \"open\")]((\"popular\", \"comment\", \"taboo\", \"shorts\", function " ascii
    $s6 = "boardTampon[(\"liberal\", \"instrument\", \"department\", \"open\")]((\"popular\", \"comment\", \"taboo\", \"shorts\", function " ascii
    $s7 = "} catch (toneBus) {};" fullword ascii

  condition:
    uint16(0) == 0x6f76 and
    1 of ($x*) and all of them
}