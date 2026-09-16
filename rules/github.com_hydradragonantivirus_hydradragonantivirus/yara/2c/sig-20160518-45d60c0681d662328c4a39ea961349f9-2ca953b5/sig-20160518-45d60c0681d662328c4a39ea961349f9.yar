rule sig_20160518_45d60c0681d662328c4a39ea961349f9 {
  meta:
    description = "datamaliciousorder - file 20160518_45d60c0681d662328c4a39ea961349f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2141280de0f579f62cb3cfe266d2389b1f857862ebf7d7dd937f6457c695d049"

  strings:
    $s1  = "milling = ((\"nutten\", \"representations\", \"terrorist\", \"headquarters\", \"pVvPawSEdk\") + \"uVBQGzpH\").hammock2();" fullword ascii
    $s2  = "weasel = ((\"argue\", \"executed\", \"seeker\", \"angels\", \"EoCadoGqhJEN\") + \"qBYCkySY\").hammock2();" fullword ascii
    $s3  = "        smoothness[(milling + \"o\"+(\"monastic\",\"jaguar\",\"inflame\",\"herald\",\"masque\",\"javascript\",\"dived\",\"cabine" ascii
    $s4  = "secretary(\"aHR0cDovLw==\".hammock4()+\"\\u0062\\u0069\\u006E\\u0074\\u0061\\u006E\\u0067\\u0066\\u0061\\u006A\\u0061\\u0072\"+" ascii
    $s5  = "var forest=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".hammock4())&&saucer[\"c3RhdHVz\".hammock4()] +\"\"==\"MjAw\".hammock4" ascii
    $s6  = "var forest=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".hammock4())&&saucer[\"c3RhdHVz\".hammock4()] +\"\"==\"MjAw\".hammock4" ascii
    $s7  = "var finnish = [strongly, grandparents,proposals,  \"\"+\".\"+(\"bullying\",\"thomas\",\"formative\",\"vindicate\",\"healthy\",\"" ascii
    $s8  = "  heady = [];" fullword ascii
    $s9  = "        smoothness[(milling + \"o\"+(\"monastic\",\"jaguar\",\"inflame\",\"herald\",\"masque\",\"javascript\",\"dived\",\"cabine" ascii
    $s10 = "      heady[ i ] = -1;" fullword ascii
    $s11 = "function secretary(gelatine, idioms) {" fullword ascii
    $s12 = "String.prototype.hammock2 = function () {" fullword ascii
    $s13 = "compression = \"_F2_\";" fullword ascii
    $s14 = "var eligibility = finnish.pop().split(\">\");" fullword ascii
    $s15 = "secretary(\"aHR0cDovLw==\".hammock4()+\"\\u0062\\u0069\\u006E\\u0074\\u0061\\u006E\\u0067\\u0066\\u0061\\u006A\\u0061\\u0072\"+" ascii
    $s16 = "String.prototype.hammock = function () {" fullword ascii
    $s17 = "String.prototype.hammock4 = function() {" fullword ascii
    $s18 = "var sheer = reliable[finnish.shift()](finnish.shift());" fullword ascii
    $s19 = "var saucer = new parsons(eligibility[0]);" fullword ascii
    $s20 = "var reliable = new parsons(eligibility[1]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}