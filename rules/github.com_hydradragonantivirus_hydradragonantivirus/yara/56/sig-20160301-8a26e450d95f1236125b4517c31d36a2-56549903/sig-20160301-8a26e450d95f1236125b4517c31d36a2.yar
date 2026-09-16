rule sig_20160301_8a26e450d95f1236125b4517c31d36a2 {
  meta:
    description = "datamaliciousorder - file 20160301_8a26e450d95f1236125b4517c31d36a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "125b18fabd21677b2649896161b98746137dbcff827956a43de8d7db29ad573d"

  strings:
    $s1 = "forceSaturation = anarchyDirector[(\"e\\u0073\\u0073\" + \"\\u0061\" + \"\\u0079\", \"po\" + \"p\\u0075l\\u0061\" + \"\\u0072\"," ascii
    $s2 = "06d\\u0065\" + \"n\\u0074\", \"\\u0070\\u0072ev\" + \"e\" + \"nt\\u0069\" + \"\\u0076\" + \"\\u0065\", function String.prototype" ascii
    $s3 = "while (industrialParadox[(\"soci\\u0061\" + \"l\", \"\\u0072ea\\u0064\" + \"\\u0079\" + \"st\\u0061\" + \"\\u0074\\u0065\")] < 2" ascii
    $s4 = "anarchyDirector = ((([+!+[]])), this);" fullword ascii
    $s5 = "} catch (listTransplant) {};" fullword ascii

  condition:
    uint16(0) == 0x6e61 and
    all of them
}