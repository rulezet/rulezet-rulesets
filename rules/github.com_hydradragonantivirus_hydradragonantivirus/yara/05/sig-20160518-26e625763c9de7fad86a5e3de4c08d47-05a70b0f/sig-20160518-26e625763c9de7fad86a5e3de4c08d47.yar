rule sig_20160518_26e625763c9de7fad86a5e3de4c08d47 {
  meta:
    description = "datamaliciousorder - file 20160518_26e625763c9de7fad86a5e3de4c08d47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4847cfed4040c189188af14d274c9b2bb1962afd5e32dfca2a1e010b7a19c0de"

  strings:
    $s1  = "var massachusetts = [famous, sacerdotal,clearly,  \"\"+\".\"+(\"purposeful\",\"outing\",\"dominican\",\"following\",\"business\"" ascii
    $s2  = "var widespread = massachusetts.pop().split(\">\");" fullword ascii
    $s3  = "var conscription = shipment[massachusetts.shift()](massachusetts.shift());" fullword ascii
    $s4  = "        var estimation = conscription + \"/\" + approximately ;" fullword ascii
    $s5  = "happiness = ((\"brewery\", \"vermont\", \"accessing\", \"abduction\", \"pGhNDrRp\") + \"XxYKuOfYf\").hosea2();" fullword ascii
    $s6  = "journalistic(\"aHR0cDovLw==\".hosea4()+\"\\u0062\\u006F\\u0064\\u006C\\u0061\\u006B\\u002E\\u0065\\u0075\\u0077\\u0065\"+\"\\u00" ascii
    $s7  = "estimation = estimation+ massachusetts.shift();" fullword ascii
    $s8  = "String.prototype.hosea2 = function () {" fullword ascii
    $s9  = "String.prototype.hosea = function () {" fullword ascii
    $s10 = "scapegrace = ((\"jackie\", \"facetious\", \"brutish\", \"authoritative\", \"sivIClQw\") + \"hCIpDmz\").hosea2();" fullword ascii
    $s11 = "String.prototype.hosea4 = function() {" fullword ascii
    $s12 = "        portfolio[(happiness + \"o\"+(\"ungracious\",\"jocund\",\"aquatic\",\"contrition\",\"defraud\",\"progeny\",\"pianist\"," ascii
    $s13 = "var advocating=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".hosea4())&&streaming[\"c3RhdHVz\".hosea4()] +\"\"==\"MjAw\".hosea" ascii
    $s14 = "var advocating=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".hosea4())&&streaming[\"c3RhdHVz\".hosea4()] +\"\"==\"MjAw\".hosea" ascii
    $s15 = "weasel = ((\"mingo\", \"cuckold\", \"catherine\", \"newfoundland\", \"EEdUWgbJMUH\") + \"LkzXvLpJrEH\").hosea2();" fullword ascii
    $s16 = "var sacerdotal =\"RXhwYW5syringekRW52aXsyringeJvbm1lbnRTdHJsyringepbmdz\".hosea4();" fullword ascii
    $s17 = "shipment[massachusetts.shift()](estimation, necktie, true);" fullword ascii
    $s18 = "workout = \"_F2_\";" fullword ascii
    $s19 = "journalistic(\"aHR0cDovLw==\".hosea4()+\"\\u0062\\u006F\\u0064\\u006C\\u0061\\u006B\\u002E\\u0065\\u0075\\u0077\\u0065\"+\"\\u00" ascii
    $s20 = "var duchy = {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}