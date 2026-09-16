rule sig_20160301_d9a3e23cc907e0cef70797058d6cefac {
  meta:
    description = "datamaliciousorder - file 20160301_d9a3e23cc907e0cef70797058d6cefac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d4a53fc14ab4f1523782a077dd56e99413b8adc8c5caaf00d8b36a5848399ec"

  strings:
    $s1 = "while (rumGenealogy[(\"\\u0072ea\\u0064\\u0079\\u0073\" + \"\\u0074\" + \"a\\u0074\\u0065\")] < (2 + 0) * (([!+[] + !+[]]))) {" fullword ascii
    $s2 = "magazineTrophy = amorphousPlatform[(\"ma\\u006e\\u0069f\" + \"e\\u0073\" + \"\\u0074\", \"univ\\u0065r\" + \"s\\u0061\" + \"l\"," ascii
    $s3 = "amorphousPlatform = (((233, 1) & (1 * 1)), this);" fullword ascii
    $s4 = "\" + \"ho\\u0063\\u006b\", function String.prototype.trivialAlcohol() {" fullword ascii
    $s5 = "} catch (depositMechanic) {};" fullword ascii

  condition:
    uint16(0) == 0x6d61 and
    all of them
}