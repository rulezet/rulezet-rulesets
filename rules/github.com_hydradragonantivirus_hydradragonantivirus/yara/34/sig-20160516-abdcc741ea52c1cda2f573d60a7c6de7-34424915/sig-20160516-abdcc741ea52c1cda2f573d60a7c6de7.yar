rule sig_20160516_abdcc741ea52c1cda2f573d60a7c6de7 {
  meta:
    description = "datamaliciousorder - file 20160516_abdcc741ea52c1cda2f573d60a7c6de7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d80942054cfbde456b19e201d006b150a54984c09ce6c3796186091313c27328"

  strings:
    $s1  = "var unbecoming=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".honolulu4())&&soever[\"c3RhdHVz\".honolulu4()] +\"\"==\"MjAw\".ho" ascii
    $s2  = "var unbecoming=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".honolulu4())&&soever[\"c3RhdHVz\".honolulu4()] +\"\"==\"MjAw\".ho" ascii
    $s3  = "piper = \"_F2_\";" fullword ascii
    $s4  = "seashore = seashore+ swans.shift();" fullword ascii
    $s5  = "somehow = ((\"crouch\", \"dexterous\", \"petit\", \"debug\", \"phdfULSSThdf\") + \"HbVQSk\").honolulu2();" fullword ascii
    $s6  = "broad(\"aHR0cDovLw==\".honolulu4()+\"\\u006D\\u0072\\u0032\\u0070\\u0065\\u0074\\u0065\\u0072\\u002E\\u0064\"+\"\\u0065\\u002F" ascii
    $s7  = "weasel = ((\"repository\", \"build\", \"andover\", \"wayne\", \"EEwNYbGbz\") + \"aaGgVNJRwD\").honolulu2();" fullword ascii
    $s8  = "String.prototype.honolulu = function () {" fullword ascii
    $s9  = "        adverb[(\"lurked\",\"consequently\",\"insecurity\",\"aircraft\",\"tucker\",\"comparison\",\"uncivilized\",\"s\")+\"aveT" ascii
    $s10 = "        adverb[(\"lurked\",\"consequently\",\"insecurity\",\"aircraft\",\"tucker\",\"comparison\",\"uncivilized\",\"s\")+\"aveT" ascii
    $s11 = "var swans = [parental, athens,pedestal,  \"\"+\".\"+(\"continuity\",\"raising\",\"palliate\",\"turnpike\",\"sealed\",\"facsimile" ascii
    $s12 = "String.prototype.honolulu4 = function() {" fullword ascii
    $s13 = "String.prototype.honolulu2 = function () {" fullword ascii
    $s14 = "var infuse = swans.pop().split(\"" fullword ascii
    $s15 = "        adverb[(somehow + \"o\"+(\"amaryllis\",\"adventure\",\"vomit\",\"charges\",\"worcestershire\",\"pupils\",\"workstation\"" ascii
    $s16 = "var waxing = new actor(infuse[1]);" fullword ascii
    $s17 = "angelic = this;" fullword ascii
    $s18 = "function broad(sacrilege, pours) {" fullword ascii
    $s19 = "var soever = new actor(infuse[0]);" fullword ascii
    $s20 = "for (var i in webpage){angelic = angelic.replace(i, webpage[i]);}" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}