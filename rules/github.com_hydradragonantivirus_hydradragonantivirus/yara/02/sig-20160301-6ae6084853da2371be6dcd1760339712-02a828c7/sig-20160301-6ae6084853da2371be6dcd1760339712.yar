rule sig_20160301_6ae6084853da2371be6dcd1760339712 {
  meta:
    description = "datamaliciousorder - file 20160301_6ae6084853da2371be6dcd1760339712.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46740e106754e31264117a4fad73c6d133d9eeeff50418cec84552ab6d2db620"

  strings:
    $s1 = "publicationTechnical = ((3 - (26 / 13)), this);" fullword ascii
    $s2 = "while(registrationSymbol[(\"\\u0073tud\" + \"i\\u006f\", \"vo\" + \"\\u006c\\u0074\", \"t\\u0072ivi\" + \"al\", \"\\u0072\" + \"" ascii
    $s3 = "while(registrationSymbol[(\"\\u0073tud\" + \"i\\u006f\", \"vo\" + \"\\u006c\\u0074\", \"t\\u0072ivi\" + \"al\", \"\\u0072\" + \"" ascii
    $s4 = "practicalDistant[(\"cl\\u0061\\u0073\\u0073\", function String.prototype.axiomOperator() {" fullword ascii
    $s5 = "} catch(facadeMeridian) {};" fullword ascii

  condition:
    uint16(0) == 0x7570 and
    all of them
}