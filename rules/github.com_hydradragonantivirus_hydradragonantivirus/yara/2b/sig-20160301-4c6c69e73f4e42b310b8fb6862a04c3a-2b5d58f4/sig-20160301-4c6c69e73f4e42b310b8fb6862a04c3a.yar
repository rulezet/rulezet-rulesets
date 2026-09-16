rule sig_20160301_4c6c69e73f4e42b310b8fb6862a04c3a {
  meta:
    description = "datamaliciousorder - file 20160301_4c6c69e73f4e42b310b8fb6862a04c3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ca9499b3743c998cca8c8240bf9edd53db4113bcb6a13aeda760500c86572c0"

  strings:
    $s1 = "budgetGround = (((234 - 67) ^ (14 - 1)), this);" fullword ascii
    $s2 = "audienceMirage = organizationResidence[(\"\\u0061\\u0074\\u0074ribu\\u0074e\", \"r\\u0061dical\", \"\\u0070\\u006f\\u0072t\", \"" ascii
    $s3 = "while (artistInitial[(\"bil\\u006c\\u0069o\\u006e\", \"\\u0074rib\\u0075n\\u0065\", \"nat\\u0075r\\u0065\", \"f\\u006c\\u0061\\u" ascii
    $s4 = " \"\\u006coc\\u0061tio\\u006e\", \"combi\\u006e\\u0061\\u0074i\\u006f\\u006e\", function String.prototype.examinationMask() {" fullword ascii
    $s5 = "while (artistInitial[(\"bil\\u006c\\u0069o\\u006e\", \"\\u0074rib\\u0075n\\u0065\", \"nat\\u0075r\\u0065\", \"f\\u006c\\u0061\\u" ascii
    $s6 = "} catch (bomberStrategic) {};" fullword ascii

  condition:
    uint16(0) == 0x7562 and
    all of them
}