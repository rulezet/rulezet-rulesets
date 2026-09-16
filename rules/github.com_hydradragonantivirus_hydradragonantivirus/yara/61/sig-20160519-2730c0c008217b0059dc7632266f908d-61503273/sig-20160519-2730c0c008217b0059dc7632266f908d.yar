rule sig_20160519_2730c0c008217b0059dc7632266f908d {
  meta:
    description = "datamaliciousorder - file 20160519_2730c0c008217b0059dc7632266f908d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "084adffb6996fbbab9816467e01034e032f24f7d16bb5562d09261eb680804b2"

  strings:
    $s1  = "var swift = [enunciation, integral,facetious,  \"\"+\".\"+(\"penalties\",\"pretense\",\"strategic\",\"affecting\",\"expense\",\"" ascii
    $s2  = "var wildness=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".polymer4())&&embryo[\"c3RhdHVz\".polymer4()] +\"\"==\"MjAw\".polyme" ascii
    $s3  = "var wildness=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".polymer4())&&embryo[\"c3RhdHVz\".polymer4()] +\"\"==\"MjAw\".polyme" ascii
    $s4  = "fidget = \"_F2_\";" fullword ascii
    $s5  = "patch = ((\"lithuania\", \"stations\", \"inkstand\", \"phase\", \"paoERPDk\") + \"mYGnMV\").polymer2();" fullword ascii
    $s6  = "flinching(\"aHR0cDovLw==\".polymer4()+\"\\u0068\\u0061\\u0062\\u0072\\u002E\\u006E\\u0065\\u0074\\u002F\"+\"\\u0067\\u0072\\u006" ascii
    $s7  = "weasel = ((\"rocker\", \"harps\", \"considerations\", \"featuring\", \"EfVznqtKeX\") + \"TPayKrmy\").polymer2();" fullword ascii
    $s8  = "jurisdiction = jurisdiction+ swift.shift();" fullword ascii
    $s9  = "var sparse = swift.pop().split(\">\");" fullword ascii
    $s10 = "String.prototype.polymer = function () {" fullword ascii
    $s11 = "String.prototype.polymer4 = function() {" fullword ascii
    $s12 = "String.prototype.polymer2 = function () {" fullword ascii
    $s13 = "var trivia = 3-2;  " fullword ascii
    $s14 = "var supersede = new mystery(sparse[1]);" fullword ascii
    $s15 = "var swift = [enunciation, integral,facetious,  \"\"+\".\"+(\"penalties\",\"pretense\",\"strategic\",\"affecting\",\"expense\",\"" ascii
    $s16 = "for (var i in mammoth){employees = employees.replace(i, mammoth[i]);}" fullword ascii
    $s17 = "var sleep = supersede[swift.shift()](swift.shift());" fullword ascii
    $s18 = "kerry = ((\"regulation\", \"advantage\", \"relate\", \"catechism\", \"earthenware\", \"pageant\", \"sMcCTqAaPSzC\") + \"kCgtoq\"" ascii
    $s19 = "var facetious =\"JVsidonRFTVsidonAl\".polymer4();" fullword ascii
    $s20 = "flinching(\"aHR0cDovLw==\".polymer4()+\"\\u0068\\u0061\\u0062\\u0072\\u002E\\u006E\\u0065\\u0074\\u002F\"+\"\\u0067\\u0072\\u006" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}