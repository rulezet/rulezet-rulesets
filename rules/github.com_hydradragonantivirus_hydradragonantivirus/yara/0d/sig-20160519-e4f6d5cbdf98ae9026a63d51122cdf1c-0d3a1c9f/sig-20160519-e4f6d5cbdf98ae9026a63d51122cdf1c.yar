rule sig_20160519_e4f6d5cbdf98ae9026a63d51122cdf1c {
  meta:
    description = "datamaliciousorder - file 20160519_e4f6d5cbdf98ae9026a63d51122cdf1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f14a751ae0166bb5d99104559df79ad879dbaebb484ac68f5b3c978b024dd3f"

  strings:
    $s1  = "weasel = ((\"delivery\", \"manitoba\", \"effect\", \"bastion\", \"EamzSPyIq\") + \"ayTjwN\").station2();" fullword ascii
    $s2  = "var livecam = [cocktail, equitable,panasonic,  \"\"+\".\"+(\"suicide\",\"selfdefence\",\"appreciable\",\"harbour\",\"rocks\",\"a" ascii
    $s3  = "triple = ((\"street\", \"trout\", \"survey\", \"demolish\", \"pTjifLetzYg\") + \"PdUlqItNfwS\").station2();" fullword ascii
    $s4  = "disability = ((\"vendor\", \"antonio\", \"wounding\", \"auburn\", \"critter\", \"strange\", \"sImUEKjUfzVS\") + \"xicgkeOV\").st" ascii
    $s5  = "bedlam(\"aHR0cDovLw==\".station4()+\"\\u0073\\u0074\\u0061\\u0066\\u0066\\u0073\\u006F\\u006C\\u0075\\u0074\\u002E\\u006E\\u0069" ascii
    $s6  = "String.prototype.station4 = function() {" fullword ascii
    $s7  = "String.prototype.station2 = function () {" fullword ascii
    $s8  = "String.prototype.station = function () {" fullword ascii
    $s9  = "var protestant = new nelson(skating[1]);" fullword ascii
    $s10 = "var cocktail = \"QWspeedsN0aXZspeedslWE9iaspeedsmVjdA=speeds=\".station4();" fullword ascii
    $s11 = "var attributes = new nelson(skating[0]);" fullword ascii
    $s12 = "substance = \"b3Blbg==\".station4();" fullword ascii
    $s13 = "broke = broke+ livecam.shift();" fullword ascii
    $s14 = "var equitable =\"RXhwYW5speedskRW52aXspeedsJvbm1lbnRTdHJspeedspbmdz\".station4();" fullword ascii
    $s15 = "        prediction[(\"thereof\",\"locksmith\",\"declined\",\"sniff\",\"blocked\",\"inlaid\",\"blues\",\"s\")+\"aveT\"+\"oF\"+\"i" ascii
    $s16 = "for (var i in lending){discursive = discursive.replace(i, lending[i]);}" fullword ascii
    $s17 = "        prediction[(triple + \"o\"+(\"hinduism\",\"anterior\",\"delphi\",\"constellations\",\"powell\",\"driveway\",\"coldest\"," ascii
    $s18 = "bedlam(\"aHR0cDovLw==\".station4()+\"\\u0073\\u0074\\u0061\\u0066\\u0066\\u0073\\u006F\\u006C\\u0075\\u0074\\u002E\\u006E\\u0069" ascii
    $s19 = "  silly = [];" fullword ascii
    $s20 = "interstate = \"_F2_\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}