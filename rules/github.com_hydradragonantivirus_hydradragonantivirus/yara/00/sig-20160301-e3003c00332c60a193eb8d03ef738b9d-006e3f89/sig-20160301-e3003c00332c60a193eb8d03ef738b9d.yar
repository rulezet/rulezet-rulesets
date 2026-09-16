rule sig_20160301_e3003c00332c60a193eb8d03ef738b9d {
  meta:
    description = "datamaliciousorder - file 20160301_e3003c00332c60a193eb8d03ef738b9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17d8fd085e5223a74dbfd317c566dfcaf925c5898311df30ed6d36f401c1b2ba"

  strings:
    $s1 = "mandateNumeral = (((68, 37) ^ (107, 157, 182)), this);" fullword ascii
    $s2 = "while(tractBureau[(\"terr\\u0069\\u0074ory\", \"p\\u0072\\u0069c\\u0065-\\u006c\\u0069st\", \"i\\u006e\\u0066\\u006c\\u0061t\\u0" ascii
    $s3 = "while(tractBureau[(\"terr\\u0069\\u0074ory\", \"p\\u0072\\u0069c\\u0065-\\u006c\\u0069st\", \"i\\u006e\\u0066\\u006c\\u0061t\\u0" ascii
    $s4 = "u0073\")]((\"\\u006fb\\u006a\\u0065ctiv\\u0065\", \"p\\u0061\\u0072ole\", function String.prototype.classificationRace() {" fullword ascii
    $s5 = "cafeOcean = syntaxInterval[(\"\\u0045\\u0078pa\\u006e\\u0064\\u0045n\\u0076i\\u0072\\u006f\\u006e\\u006de\\u006e\\u0074S\\u0074r" ascii
    $s6 = "} catch(dogmaSanction) {};" fullword ascii

  condition:
    uint16(0) == 0x616d and
    all of them
}