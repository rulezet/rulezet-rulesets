rule sig_20160517_aab7ef34bb6c7a7d2f9d95e6404eb3d7 {
  meta:
    description = "datamaliciousorder - file 20160517_aab7ef34bb6c7a7d2f9d95e6404eb3d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3724b6b4f6eceb597396e674fca03d74bd95c6f737065643cd4ef5364c0e1855"

  strings:
    $s1  = "valley = valley+ threaded.shift();" fullword ascii
    $s2  = "var therapeutic = threaded.pop().split(\"" fullword ascii
    $s3  = "var threaded = [immune, formatting,fecundity,  \"\"+\".\"+(\"erotic\",\"adjectives\",\"guillotine\",\"effect\",\"youth\",\"flawl" ascii
    $s4  = "var phone=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".tourist4())&&originally[\"c3RhdHVz\".tourist4()] +\"\"==\"MjAw\".touri" ascii
    $s5  = "var phone=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".tourist4())&&originally[\"c3RhdHVz\".tourist4()] +\"\"==\"MjAw\".touri" ascii
    $s6  = "weasel = ((\"flour\", \"toolbox\", \"minnesota\", \"qualified\", \"EBQHsqi\") + \"QyubVp\").tourist2();" fullword ascii
    $s7  = "String.prototype.tourist = function () {" fullword ascii
    $s8  = "String.prototype.tourist4 = function() {" fullword ascii
    $s9  = "var probation = glucose[threaded.shift()](threaded.shift());" fullword ascii
    $s10 = "String.prototype.tourist2 = function () {" fullword ascii
    $s11 = "var threaded = [immune, formatting,fecundity,  \"\"+\".\"+(\"erotic\",\"adjectives\",\"guillotine\",\"effect\",\"youth\",\"flawl" ascii
    $s12 = "glucose[threaded.shift()](valley, jesse, true);" fullword ascii
    $s13 = "var intolerant = this[threaded.shift()];" fullword ascii
    $s14 = "            originally[combated]((\"bradford\",\"assistance\",\"G\" + weasel) + (\"sammy\",\"virtually\",\"bristol\",\"flimsy\"," ascii
    $s15 = "            originally[combated]((\"bradford\",\"assistance\",\"G\" + weasel) + (\"sammy\",\"virtually\",\"bristol\",\"flimsy\"," ascii
    $s16 = "var originally = new intolerant(therapeutic[0]);" fullword ascii
    $s17 = "  external = [];" fullword ascii
    $s18 = "function plants(impertinence, august) {" fullword ascii
    $s19 = "var daunt = {" fullword ascii
    $s20 = "ence, false);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}