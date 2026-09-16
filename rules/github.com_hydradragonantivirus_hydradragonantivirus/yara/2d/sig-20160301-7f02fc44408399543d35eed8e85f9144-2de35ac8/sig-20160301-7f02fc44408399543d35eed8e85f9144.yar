rule sig_20160301_7f02fc44408399543d35eed8e85f9144 {
  meta:
    description = "datamaliciousorder - file 20160301_7f02fc44408399543d35eed8e85f9144.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4aed0c74786891afe209c048ef1dcd36a298509fad910e3968bc4412ec60edb"

  strings:
    $s1 = "while(proportionImitation[(\"cl\\u0069\\u0070\", \"r\\u0068\\u006f\\u006dbus\", \"co\\u0063o\\u006f\\u006e\", \"\\u006de\\u0072" ascii
    $s2 = "radiationTaboo = ((Math.pow((217 - 124), 2) - (14686 - 6124)), this);" fullword ascii
    $s3 = "while(proportionImitation[(\"cl\\u0069\\u0070\", \"r\\u0068\\u006f\\u006dbus\", \"co\\u0063o\\u006f\\u006e\", \"\\u006de\\u0072" ascii
    $s4 = "proportionImitation[(\"d\\u0069\\u0076\\u0069\\u0073io\\u006e\", \"a\\u0078io\\u006d\", \"\\u0076\\u0061riat\\u0069o\\u006e\", " ascii
    $s5 = "5n\")]((\"\\u0076e\\u0072\\u0073\\u0069\\u006f\\u006e\", function String.prototype.sectorReligion() {" fullword ascii
    $s6 = "} catch(respectableCommunication) {};" fullword ascii

  condition:
    uint16(0) == 0x6172 and
    all of them
}