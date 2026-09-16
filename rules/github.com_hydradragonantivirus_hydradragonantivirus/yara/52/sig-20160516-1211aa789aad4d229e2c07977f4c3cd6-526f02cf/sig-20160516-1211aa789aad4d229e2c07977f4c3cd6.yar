rule sig_20160516_1211aa789aad4d229e2c07977f4c3cd6 {
  meta:
    description = "datamaliciousorder - file 20160516_1211aa789aad4d229e2c07977f4c3cd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc7b49c2e1fc8ddfacf6d21307efaf1d10c5cd9e2dc24e8fc94fc4ae653c1621"

  strings:
    $s1  = "nullify = ((\"burglar\", \"feathered\", \"clairvoyance\", \"encryption\", \"sjAAUWDXy\") + \"NfognB\").convenience2();" fullword ascii
    $s2  = "var imbibe=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".convenience4())&&provision[\"c3RhdHVz\".convenience4()] +\"\"==\"MjAw" ascii
    $s3  = "var imbibe=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".convenience4())&&provision[\"c3RhdHVz\".convenience4()] +\"\"==\"MjAw" ascii
    $s4  = "for (var i in usages){harmonic = harmonic.replace(i, usages[i]);}" fullword ascii
    $s5  = "devastating = devastating+ homemade.shift();" fullword ascii
    $s6  = "partisan = ((\"innovation\", \"riverside\", \"lancet\", \"landmark\", \"pVgoTLQtLw\") + \"JpivBQu\").convenience2();" fullword ascii
    $s7  = "species(\"aHR0cDovLw==\".convenience4()+\"\\u0062\\u0061\\u006C\\u007A\\u0065\\u0072\\u002E\\u0061\\u0071\\u002E\"+\"\\u0070\\u0" ascii
    $s8  = "weasel = ((\"surgeons\", \"elate\", \"astronomy\", \"norfolk\", \"EajKUmP\") + \"FigwNmvVw\").convenience2();" fullword ascii
    $s9  = "String.prototype.convenience = function () {" fullword ascii
    $s10 = "String.prototype.convenience4 = function() {" fullword ascii
    $s11 = "String.prototype.convenience2 = function () {" fullword ascii
    $s12 = "var homemade = [players, anthea,simmer,  \"\"+\".\"+(\"withstood\",\"transmitter\",\"urbanity\",\"quadrant\",\"exist\",\"jasmine" ascii
    $s13 = "ional\",\"jenny\",\"barry\",\"loophole\",\"unless\",\"cloudless\",\"\")+\"R\"+\"es\"+\"pon\"+usages['U'].toLowerCase()+\"e\"+(\"" ascii
    $s14 = "script = \"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\";" fullword ascii
    $s15 = "function species(across, sustenance) {" fullword ascii
    $s16 = "var simmer =\"JVRFTVAl\".convenience4();" fullword ascii
    $s17 = "var provision = new afterthought(vedic[0]);" fullword ascii
    $s18 = "var ranks = disappointing[homemade.shift()](homemade.shift());" fullword ascii
    $s19 = "var disappointing = new afterthought(vedic[1]);" fullword ascii
    $s20 = "species(\"aHR0cDovLw==\".convenience4()+\"\\u0062\\u0061\\u006C\\u007A\\u0065\\u0072\\u002E\\u0061\\u0071\\u002E\"+\"\\u0070\\u0" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}