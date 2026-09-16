rule sig_20160301_1e8d836e09500ca2353492e66eaca14e {
  meta:
    description = "datamaliciousorder - file 20160301_1e8d836e09500ca2353492e66eaca14e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fe399befd8887fabe75bebc3b660dbd572d428ed81acc1b1709053f9a7470b7"

  strings:
    $s1 = "colonyCommittee = (((Math.pow(27, 2) - 697) / (21 ^ 53)), this);" fullword ascii
    $s2 = "\\u0072\\u0074\") + (\"s\" + \"\\u0077\\u0069\" + \"\\u0074c\" + \"h\", function String.prototype.impressionProcedure() {" fullword ascii
    $s3 = "while(appealColony[(\"r\\u0065p\" + \"\\u0075\\u0062\\u006c\" + \"i\\u0063\", \"r\\u006ft\" + \"\\u0061\" + \"t\" + \"\\u0069o" ascii
    $s4 = "while(appealColony[(\"r\\u0065p\" + \"\\u0075\\u0062\\u006c\" + \"i\\u0063\", \"r\\u006ft\" + \"\\u0061\" + \"t\" + \"\\u0069o" ascii
    $s5 = "momentStop = platformTender[(\"\\u0045\\u0078\" + \"\\u0070\" + \"\\u0061\\u006ed\\u0045\" + \"n\\u0076\" + \"i\\u0072o\\u006e" ascii
    $s6 = "} catch(absorptionFirm) {};" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    all of them
}