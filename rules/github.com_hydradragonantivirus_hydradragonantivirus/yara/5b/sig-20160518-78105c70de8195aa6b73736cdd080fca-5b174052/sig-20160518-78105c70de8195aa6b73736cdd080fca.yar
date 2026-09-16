rule sig_20160518_78105c70de8195aa6b73736cdd080fca {
  meta:
    description = "datamaliciousorder - file 20160518_78105c70de8195aa6b73736cdd080fca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6e1ec05d242840f530990073a1d59122d4dce3813fbbddf5199cacabe437079"

  strings:
    $s1  = "var whiles =\"JVbloggerRFTVbloggerAl\".vessel4();" fullword ascii
    $s2  = "var refutation =\"RXhwYW5bloggerkRW52aXbloggerJvbm1lbnRTdHJbloggerpbmdz\".vessel4();" fullword ascii
    $s3  = "var guitar = [requesting, refutation,whiles,  \"\"+\".\"+(\"siberia\",\"callow\",\"portrait\",\"trojan\",\"campbell\",\"antipode" ascii
    $s4  = "var belfast=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".vessel4())&&nearby[\"c3RhdHVz\".vessel4()] +\"\"==\"MjAw\".vessel4()" ascii
    $s5  = "var belfast=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".vessel4())&&nearby[\"c3RhdHVz\".vessel4()] +\"\"==\"MjAw\".vessel4()" ascii
    $s6  = "for (var i in circuitous){imprison = imprison.replace(i, circuitous[i]);}" fullword ascii
    $s7  = "    nearby[course + (\"windpipe\",\"sodium\",\"end\")]();" fullword ascii
    $s8  = "var circuitous = {" fullword ascii
    $s9  = "jubilee = ((\"providence\", \"interpolation\", \"perceived\", \"despite\", \"pHSLjmAHL\") + \"UPJHJLiLRn\").vessel2();" fullword ascii
    $s10 = "lilac = lilac+ guitar.shift();" fullword ascii
    $s11 = "course = ((\"adapter\", \"conciliate\", \"ulcer\", \"monaco\", \"sVPOYyA\") + \"HoTAANtGE\").vessel2();" fullword ascii
    $s12 = "weasel = ((\"hustle\", \"named\", \"going\", \"mitigation\", \"ErWpDQeMKLYa\") + \"StoVncge\").vessel2();" fullword ascii
    $s13 = "alchemy(\"aHR0cDovLw==\".vessel4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0061\\u0072\\u0074\\u0068\\u002D\\u0073\\u0061\\u006E" ascii
    $s14 = "String.prototype.vessel4 = function() {" fullword ascii
    $s15 = "String.prototype.vessel = function () {" fullword ascii
    $s16 = "String.prototype.vessel2 = function () {" fullword ascii
    $s17 = "tartar[guitar.shift()](lilac, radiate, true);" fullword ascii
    $s18 = "imprison = this;" fullword ascii
    $s19 = "var heinous = this[guitar.shift()];" fullword ascii
    $s20 = "var haven = 0;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}