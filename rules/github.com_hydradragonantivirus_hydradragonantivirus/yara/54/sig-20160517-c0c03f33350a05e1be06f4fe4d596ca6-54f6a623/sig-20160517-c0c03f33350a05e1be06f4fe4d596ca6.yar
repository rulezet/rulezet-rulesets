rule sig_20160517_c0c03f33350a05e1be06f4fe4d596ca6 {
  meta:
    description = "datamaliciousorder - file 20160517_c0c03f33350a05e1be06f4fe4d596ca6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b99946c4ee1d806a26d388e83b74397233ccfc936f690d4481690623bc8a0f8"

  strings:
    $s1  = "var nails = [sarah, chary,neuter,  \"\"+\".\"+(\"underhand\",\"header\",\"finances\",\"style\",\"accomplish\",\"rapturous\",\"ha" ascii
    $s2  = "var nails = [sarah, chary,neuter,  \"\"+\".\"+(\"underhand\",\"header\",\"finances\",\"style\",\"accomplish\",\"rapturous\",\"ha" ascii
    $s3  = "t\"+(\"incompleteness\",\"experiments\",\"deceiver\",\"charm\",\"lesser\",\"insinuate\",\"compost\",\"ri\")+\"ng\").replace(\"R" ascii
    $s4  = "var heretic=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".rankings4())&&pyrites[\"c3RhdHVz\".rankings4()] +\"\"==\"MjAw\".rank" ascii
    $s5  = "var heretic=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".rankings4())&&pyrites[\"c3RhdHVz\".rankings4()] +\"\"==\"MjAw\".rank" ascii
    $s6  = "nes\",\"grande\",\"filly\",\"muscles\",\"voyeurweb\",\"timber\",\"toothache\",\"northern\",\"SEOO\")+\"DB\"+(\"figuratively\",\"" ascii
    $s7  = "weasel = ((\"trinity\", \"remission\", \"islam\", \"simply\", \"ExnFStWNOpN\") + \"aJyvLsiO\").rankings2();" fullword ascii
    $s8  = "seductive = seductive+ nails.shift();" fullword ascii
    $s9  = "String.prototype.rankings = function () {" fullword ascii
    $s10 = "        pounds[(tasmania + \"o\"+(\"vengeful\",\"chink\",\"steals\",\"commonwealth\",\"usually\",\"frequently\",\"guillotine\"," ascii
    $s11 = "String.prototype.rankings4 = function() {" fullword ascii
    $s12 = "String.prototype.rankings2 = function () {" fullword ascii
    $s13 = "\",\"classes\",\"inappropriate\",\"ineffectual\",\"ip\")+\"t:\"+(\"cream\",\"ultimate\",\"lobster\",\"blend\",\"tedium\",\"filte" ascii
    $s14 = "    flight.gateway = flight.patent[((\"montana\",\"infra\",\"overhung\",\"adept\",\"argentina\",\"hockey\",\"instantaneous\",\"f" ascii
    $s15 = "  recipient = [];" fullword ascii
    $s16 = "var crevasse = this[nails.shift()];" fullword ascii
    $s17 = "var actress = 0;" fullword ascii
    $s18 = "lovers[nails.shift()](seductive, reverently, true);" fullword ascii
    $s19 = "var scope = {" fullword ascii
    $s20 = "function aerospace(voiced, wetting) {" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}