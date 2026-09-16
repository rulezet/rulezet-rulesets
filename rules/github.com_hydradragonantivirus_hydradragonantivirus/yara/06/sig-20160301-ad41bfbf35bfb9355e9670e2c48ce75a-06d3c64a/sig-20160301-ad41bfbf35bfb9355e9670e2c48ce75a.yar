rule sig_20160301_ad41bfbf35bfb9355e9670e2c48ce75a {
  meta:
    description = "datamaliciousorder - file 20160301_ad41bfbf35bfb9355e9670e2c48ce75a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49ea8c46bde4c219a968399169dfb88002facd0fc4888e62909108b5e3417a91"

  strings:
    $s1 = "illustrateAbsurd[(\"va\\u0063a\\u006e\" + \"\\u0074\", \"w\\u0072\\u0069t\\u0065\")](reservoirDisk[(\"or\\u0069g\" + \"i\\u006ea" ascii
    $s2 = "while(reservoirDisk[(\"\\u0070\" + \"\\u0068\\u0061\" + \"s\\u0065\", \"r\" + \"\\u0065\" + \"\\u0061dy\" + \"\\u0073\" + \"\\u0" ascii
    $s3 = "illustrateAbsurd[(\"va\\u0063a\\u006e\" + \"\\u0074\", \"w\\u0072\\u0069t\\u0065\")](reservoirDisk[(\"or\\u0069g\" + \"i\\u006ea" ascii
    $s4 = "while(reservoirDisk[(\"\\u0070\" + \"\\u0068\\u0061\" + \"s\\u0065\", \"r\" + \"\\u0065\" + \"\\u0061dy\" + \"\\u0073\" + \"\\u0" ascii
    $s5 = "sexualBattery = (((1 * 1) & (1 + 0)), this);" fullword ascii
    $s6 = "} catch(inductionComfort) {};" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    all of them
}