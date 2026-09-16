rule sig_20160301_850f6a8798c29f060fce82553b722667 {
  meta:
    description = "datamaliciousorder - file 20160301_850f6a8798c29f060fce82553b722667.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "166cc7d4750c70b0b9eb7d7b81e274b4f91a48c3c19c776dd93a291e478e5aeb"

  strings:
    $s1 = "while (scandalNumeration[(\"d\" + \"e\\u0067\\u0072\" + \"a\\u0064\\u0061t\\u0069o\" + \"\\u006e\", \"\\u0063\\u006fnt\\u0072\" " ascii
    $s2 = "while (scandalNumeration[(\"d\" + \"e\\u0067\\u0072\" + \"a\\u0064\\u0061t\\u0069o\" + \"\\u006e\", \"\\u0063\\u006fnt\\u0072\" " ascii
    $s3 = "meration[(\"\\u0070r\" + \"ovo\\u0063a\\u0074\" + \"\\u0069\\u006f\\u006e\", function String.prototype.populationReform() {" fullword ascii
    $s4 = "inspectionGenesis = (((69 ^ 202), (1 * 1)), this);" fullword ascii
    $s5 = "    giganticAccommodation[(\"i\" + \"\\u006eter\" + \"\\u0070r\" + \"\\u0065t\", \"\\u0061\\u006e\\u0061r\" + \"\\u0063\" + \"hy" ascii
    $s6 = "} catch (magicTonic) {};" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    all of them
}