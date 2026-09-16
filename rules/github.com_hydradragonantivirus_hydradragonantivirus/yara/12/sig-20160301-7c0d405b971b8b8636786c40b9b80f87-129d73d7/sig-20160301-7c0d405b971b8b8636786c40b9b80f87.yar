rule sig_20160301_7c0d405b971b8b8636786c40b9b80f87 {
  meta:
    description = "datamaliciousorder - file 20160301_7c0d405b971b8b8636786c40b9b80f87.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca3b1b09957b7ff9d0230efaf10d1a4e379aa094b16503889db85989701f791a"

  strings:
    $s1 = "individualTick = rhombusTotal[(\"\\u0065\\u006ce\\u006de\\u006et\", \"\\u0073c\\u0068eme\", \"\\u006de\\u0074\\u0068od\", \"Ex" ascii
    $s2 = "dEn\\u0076ironme\\u006etStri\\u006egs\")]((\"a\\u006e\\u0074\\u0065nna\", \"\\u006fri\\u0067in\", \"\\u006d\\u0061nag\\u0065r\"," ascii
    $s3 = "fatalProjection = (((Math.pow(111, 2) - 12255), (97 + 111), 7 * 2 * 13), this);" fullword ascii
    $s4 = "while(medalAccuracy[(\"\\u0064e\\u0070ot\", \"\\u0069n\\u0064u\\u0073\\u0074\\u0072\\u0079\", function String.prototype.prefixIn" ascii
    $s5 = "} catch(momentReservoir) {};" fullword ascii

  condition:
    uint16(0) == 0x6166 and
    all of them
}