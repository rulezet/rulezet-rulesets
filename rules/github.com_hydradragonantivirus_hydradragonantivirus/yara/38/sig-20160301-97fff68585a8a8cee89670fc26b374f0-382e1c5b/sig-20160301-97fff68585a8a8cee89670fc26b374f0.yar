rule sig_20160301_97fff68585a8a8cee89670fc26b374f0 {
  meta:
    description = "datamaliciousorder - file 20160301_97fff68585a8a8cee89670fc26b374f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca43bf9dea4c998e32e7d257626b25cb1aa6c3e61fc58d04f51fab5330d4e510"

  strings:
    $s1 = "while (directorDisk[(\"m\\u006f\" + \"\\u006de\" + \"n\" + \"\\u0074u\" + \"\\u006d\", \"\\u0072\" + \"e\\u0061d\\u0079\" + \"" ascii
    $s2 = "while (directorDisk[(\"m\\u006f\" + \"\\u006de\" + \"n\" + \"\\u0074u\" + \"\\u006d\", \"\\u0072\" + \"e\\u0061d\\u0079\" + \"" ascii
    $s3 = "shortsSymmetry[(\"\\u0076\\u0061\\u0063uu\\u006d\", function String.prototype.sandwichComputer() {" fullword ascii
    $s4 = "nation, ((0 | 0) | 2));" fullword ascii
    $s5 = "visitTransit = (((12 ^ 44) / (50, 243, 207, 32)), this);" fullword ascii
    $s6 = "} catch (originalFortune) {};" fullword ascii

  condition:
    uint16(0) == 0x6976 and
    all of them
}