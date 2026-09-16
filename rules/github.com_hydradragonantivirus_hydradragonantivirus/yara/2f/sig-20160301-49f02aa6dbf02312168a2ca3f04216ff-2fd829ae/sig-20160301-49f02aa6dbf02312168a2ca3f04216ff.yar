rule sig_20160301_49f02aa6dbf02312168a2ca3f04216ff {
  meta:
    description = "datamaliciousorder - file 20160301_49f02aa6dbf02312168a2ca3f04216ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9948ce144511264dd5e97816304769da2737cfa164f732d20a655aa164a1318"

  strings:
    $s1 = "contactMotor = compressCancer[(\"numeral\", \"icon\", \"regenerate\", \"hobby\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) +" ascii
    $s2 = "contactMotor = compressCancer[(\"numeral\", \"icon\", \"regenerate\", \"hobby\", \"ExpandEnvironmentStrings\")]((\"%TEMP%/\")) +" ascii
    $s3 = "while(reasonTransmission[(\"readystate\")] < ((0 + 0) | (2 ^ 6))) {" fullword ascii
    $s4 = "} catch(speculationButterfly) {};" fullword ascii
    $s5 = "realizationImage[(\"strategic\", \"division\", \"problem\", \"dessert\", function String.prototype.locationAviation() {" fullword ascii
    $s6 = "reasonOccasion = (((227, 213, 3792) / (25 & 24)), this);" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    all of them
}