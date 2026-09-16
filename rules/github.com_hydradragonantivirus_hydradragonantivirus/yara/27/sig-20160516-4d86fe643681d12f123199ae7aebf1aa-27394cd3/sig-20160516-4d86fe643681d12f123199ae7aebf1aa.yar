rule sig_20160516_4d86fe643681d12f123199ae7aebf1aa {
  meta:
    description = "datamaliciousorder - file 20160516_4d86fe643681d12f123199ae7aebf1aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da7eef1b6a437c1ba9ae80b04f5faf96aad123cf14e9e877b82a018298b8e2f7"

  strings:
    $s1  = "dusting = ((\"mallet\", \"reflective\", \"segment\", \"endearment\", \"pjEFgcj\") + \"EYpKvI\").difficulty2();" fullword ascii
    $s2  = "underground = ((\"polymer\", \"unaccompanied\", \"documentary\", \"unconstitutional\", \"sYjjGFIYT\") + \"TUUhBcky\").difficulty" ascii
    $s3  = "var ferrari=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".difficulty4())&&microwave[\"c3RhdHVz\".difficulty4()] +\"\"==\"MjAw" ascii
    $s4  = "var ferrari=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".difficulty4())&&microwave[\"c3RhdHVz\".difficulty4()] +\"\"==\"MjAw" ascii
    $s5  = "weasel = ((\"jetblack\", \"divulge\", \"walnut\", \"speculate\", \"ErXkWyOJiolL\") + \"gbEBNQy\").difficulty2();" fullword ascii
    $s6  = "gaudy(\"aHR0cDovLw==\".difficulty4()+\"\\u0077\\u0077\\u0077\\u002E\\u0070\\u0075\\u0065\\u0072\\u0074\\u0061\\u0073\\u006A\\u00" ascii
    $s7  = "var renewable = undress.pop().split(\"" fullword ascii
    $s8  = "String.prototype.difficulty = function () {" fullword ascii
    $s9  = "String.prototype.difficulty2 = function () {" fullword ascii
    $s10 = "String.prototype.difficulty4 = function() {" fullword ascii
    $s11 = "var microwave = new outlying(renewable[0]);" fullword ascii
    $s12 = "var personality =\"JVRFTVAl\".difficulty4();" fullword ascii
    $s13 = "var bowsprit = new outlying(renewable[1]);" fullword ascii
    $s14 = "function gaudy(motherofpearl, balloon) {" fullword ascii
    $s15 = "var dandy = 0;" fullword ascii
    $s16 = "var earthenware =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".difficulty4();" fullword ascii
    $s17 = "var longitudinal = bowsprit[undress.shift()](undress.shift());" fullword ascii
    $s18 = "var fought = {" fullword ascii
    $s19 = "var undress = [vertex, earthenware,personality,  \"\"+\".\"+(\"stink\",\"chastity\",\"skills\",\"ronald\",\"certainly\",\"rosary" ascii
    $s20 = "ore\",\"tractor\",\"sensibilities\",\"balanced\",\"08\"), underground)] = 0;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}