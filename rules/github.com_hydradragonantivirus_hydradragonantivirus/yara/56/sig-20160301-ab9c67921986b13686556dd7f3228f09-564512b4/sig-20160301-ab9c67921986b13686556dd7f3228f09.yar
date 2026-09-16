rule sig_20160301_ab9c67921986b13686556dd7f3228f09 {
  meta:
    description = "datamaliciousorder - file 20160301_ab9c67921986b13686556dd7f3228f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f50293edd48fc828a59c5e1807fccb83f7a6b73db734b5130d7ed5c3da30051a"

  strings:
    $s1 = "sportHumane = (((80, 197, 110, 269) & (664 - 345)), this);" fullword ascii
    $s2 = "basisInternational = sportHumane[(\"WS\\u0063ri\\u0070\\u0074\")][(\"p\\u0072o\\u0067\\u0072\\u0065\\u0073\\u0073\", \"\\u006f" ascii
    $s3 = "6e\", function String.prototype.momentumSimulate() {" fullword ascii
    $s4 = "while(basisInternational[(\"m\\u0065\\u0074ap\\u0068or\", \"r\\u0065ad\\u0079\\u0073ta\\u0074\\u0065\")] < ((174, 227, 32, 2) ^ " ascii
    $s5 = "} catch(tribuneSpeculation) {};" fullword ascii

  condition:
    uint16(0) == 0x7073 and
    all of them
}