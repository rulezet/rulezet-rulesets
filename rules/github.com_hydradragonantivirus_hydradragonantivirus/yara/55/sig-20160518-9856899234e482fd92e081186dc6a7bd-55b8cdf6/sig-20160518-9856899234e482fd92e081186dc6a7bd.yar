rule sig_20160518_9856899234e482fd92e081186dc6a7bd {
  meta:
    description = "datamaliciousorder - file 20160518_9856899234e482fd92e081186dc6a7bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f29509be54d7c2f3694863f973c003afe209469e9a3f7d7c32adda7468192fe"

  strings:
    $s1  = "var deduce = [graceless, droop,privilege,  \"\"+\".\"+(\"adjustment\",\"heritage\",\"affecting\",\"garrett\",\"tepid\",\"ninetyt" ascii
    $s2  = "weasel = ((\"nevertheless\", \"woodwork\", \"picking\", \"somerset\", \"EOniIUM\") + \"TkfwUw\").temple2();" fullword ascii
    $s3  = "journeyman = ((\"crossword\", \"album\", \"hesitancy\", \"poignant\", \"pDvRbTxNuh\") + \"INPorNP\").temple2();" fullword ascii
    $s4  = "var privilege =\"JVpharmacyRFTVpharmacyAl\".temple4();" fullword ascii
    $s5  = "String.prototype.temple4 = function() {" fullword ascii
    $s6  = "        resistance[(journeyman + \"o\"+(\"broadband\",\"rocked\",\"turquoise\",\"erotic\",\"linux\",\"vulture\",\"willing\",\"ar" ascii
    $s7  = "String.prototype.temple = function () {" fullword ascii
    $s8  = "String.prototype.temple2 = function () {" fullword ascii
    $s9  = "var droop =\"RXhwYW5pharmacykRW52aXpharmacyJvbm1lbnRTdHJpharmacypbmdz\".temple4();" fullword ascii
    $s10 = "sleeve = \"b3Blbg==\".temple4();;" fullword ascii
    $s11 = "        resistance[\"d3JpdGU=\".temple4()](flows[(\"freshmen\",\"hackneyed\",\"elated\",\"elude\",\"reynard\",\"press\",\"oldwor" ascii
    $s12 = "var graceless = \"QWpharmacyN0aXZpharmacylWE9iapharmacymVjdA=pharmacy=\".temple4();" fullword ascii
    $s13 = "    willow[ login.charCodeAt( i ) ] = i;" fullword ascii
    $s14 = "login = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";" fullword ascii
    $s15 = "wearisome = wearisome+ deduce.shift();" fullword ascii
    $s16 = "        resistance[\"d3JpdGU=\".temple4()](flows[(\"freshmen\",\"hackneyed\",\"elated\",\"elude\",\"reynard\",\"press\",\"oldwor" ascii
    $s17 = "var flows = new negotiation(ringtone[0]);" fullword ascii
    $s18 = "for (var i in rudolph){supple = supple.replace(i, rudolph[i]);}" fullword ascii
    $s19 = "supple = this;" fullword ascii
    $s20 = "  willow = [];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}