rule sig_20160517_babaa1d1b071ac6f501d01cae58c080b {
  meta:
    description = "datamaliciousorder - file 20160517_babaa1d1b071ac6f501d01cae58c080b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55212944a6a1490f07ad629b65f45a936cc8d9cc594e0832a1c0e40946b77f9d"

  strings:
    $s1  = "var debtor = [friday, gentleman,wheaten,  \"\"+\".\"+(\"killed\",\"northumberland\",\"truck\",\"turtle\",\"operator\",\"hydrogen" ascii
    $s2  = "var aimed=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".brutal4())&&locally[\"c3RhdHVz\".brutal4()] +\"\"==\"MjAw\".brutal4()&" ascii
    $s3  = "var gentleman =\"RXhwYW5pathologykRW52aXpathologyJvbm1lbnRTdHJpathologypbmdz\".brutal4();" fullword ascii
    $s4  = "var aimed=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".brutal4())&&locally[\"c3RhdHVz\".brutal4()] +\"\"==\"MjAw\".brutal4()&" ascii
    $s5  = "var wheaten =\"JVpathologyRFTVpathologyAl\".brutal4();" fullword ascii
    $s6  = "tassel(\"aHR0cDovLw==\".brutal4()+\"\\u0061\\u006B\\u0064\\u0065\\u006E\\u0069\\u007A\\u006F\\u007A\\u0061\\u006C\\u0069\"+\"\\u" ascii
    $s7  = "turpentine = ((\"danny\", \"abridgment\", \"ladies\", \"saber\", \"sNppDRzLKUp\") + \"QvLKJUt\").brutal2();" fullword ascii
    $s8  = "weasel = ((\"rheumatism\", \"zones\", \"abstracted\", \"mailman\", \"EoRTYsABagCH\") + \"BhPQDGbTzs\").brutal2();" fullword ascii
    $s9  = "String.prototype.brutal2 = function () {" fullword ascii
    $s10 = "        susanna[(arrived + \"o\"+(\"craftsmen\",\"subscriber\",\"manganese\",\"esthetic\",\"oriented\",\"palmy\",\"living\",\"re" ascii
    $s11 = "String.prototype.brutal4 = function() {" fullword ascii
    $s12 = "String.prototype.brutal = function () {" fullword ascii
    $s13 = "var mourner = debtor.pop().split(\"" fullword ascii
    $s14 = "var debtor = [friday, gentleman,wheaten,  \"\"+\".\"+(\"killed\",\"northumberland\",\"truck\",\"turtle\",\"operator\",\"hydrogen" ascii
    $s15 = "for (var i in universities){florid = florid.replace(i, universities[i]);}" fullword ascii
    $s16 = "chronic = \"b3Blbg==\".brutal4();;" fullword ascii
    $s17 = "var digression = this[debtor.shift()];" fullword ascii
    $s18 = "var fiendish = 0;" fullword ascii
    $s19 = "var thesaurus = new digression(mourner[1]);" fullword ascii
    $s20 = "var instruments = thesaurus[debtor.shift()](debtor.shift());" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}