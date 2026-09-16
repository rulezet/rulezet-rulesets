rule sig_20160516_096e3a16a8f6f4ca60b261abe3bbc08a {
  meta:
    description = "datamaliciousorder - file 20160516_096e3a16a8f6f4ca60b261abe3bbc08a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "683b41aadca2dd3eee4122b53af1ffcca5c8117b04897f350d6268571a3df904"

  strings:
    $s1  = "favors\",\"charles\",\"labrador\",\"georgia\",\"ip\")+\"t:\"+(\"continence\",\"loquacity\",\"command\",\"seventyfour\",\"stabili" ascii
    $s2  = "var headquarters = standard.pop().split(\"" fullword ascii
    $s3  = "        buffer[(\"excluded\",\"inexpensive\",\"profanity\",\"scuffle\",\"lingerie\",\"processed\",\"enemy\",\"w\")+\"ri\"+\"te\"" ascii
    $s4  = "var arbor=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".squaw4())&&distinguished[\"c3RhdHVz\".squaw4()] +\"\"==\"MjAw\".squaw4" ascii
    $s5  = "var arbor=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".squaw4())&&distinguished[\"c3RhdHVz\".squaw4()] +\"\"==\"MjAw\".squaw4" ascii
    $s6  = "var distinguished = new buried(headquarters[0]);" fullword ascii
    $s7  = "var bracelet = new buried(headquarters[1]);" fullword ascii
    $s8  = "        buffer[(\"excluded\",\"inexpensive\",\"profanity\",\"scuffle\",\"lingerie\",\"processed\",\"enemy\",\"w\")+\"ri\"+\"te\"" ascii
    $s9  = "liberty = ((\"stroke\", \"blight\", \"audit\", \"linden\", \"sDMXKLuMqgBc\") + \"XLLlSMKP\").squaw2();" fullword ascii
    $s10 = "spray = ((\"neigh\", \"regulus\", \"homework\", \"steve\", \"pKREtpKDOLm\") + \"jRohaTub\").squaw2();" fullword ascii
    $s11 = "magnanimously(\"aHR0cDovLw==\".squaw4()+\"\\u0077\\u0077\\u0077\\u002E\\u0061\\u0070\\u0070\\u0061\\u0072\\u0065\\u006C\\u0062" ascii
    $s12 = "weasel = ((\"tactful\", \"finance\", \"grams\", \"acidity\", \"EkVlgCVh\") + \"IlYDKG\").squaw2();" fullword ascii
    $s13 = "String.prototype.squaw4 = function() {" fullword ascii
    $s14 = "String.prototype.squaw = function () {" fullword ascii
    $s15 = "var computation = 6/6;" fullword ascii
    $s16 = "nch\",\"elected\",\"proceeding\",\"residue\",\"digest\",\"consultant\",\"opulent\",\"visitation\",\"SEOO\")+\"DB\"+(\"magic\",\"" ascii
    $s17 = "bracelet[standard.shift()](claudia, computation, true);kjxEfDtrM = \"_F17_\";" fullword ascii
    $s18 = "String.prototype.squaw2 = function () {" fullword ascii
    $s19 = ")](waive, computation);" fullword ascii
    $s20 = "            distinguished[eliminated]((\"mistake\",\"compunction\",\"G\" + weasel) + (\"manger\",\"servitor\",\"vancouver\",\"wo" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}