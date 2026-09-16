rule sig_20160517_1aca0385eb5745089ddd7cac09df7bfe {
  meta:
    description = "datamaliciousorder - file 20160517_1aca0385eb5745089ddd7cac09df7bfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab4110df802996fe74a34ba6fa5882a350dc1a92ec020cb53ecac8a592e9a5fb"

  strings:
    $s1  = "var orange=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".rebates4())&&inferiority[\"c3RhdHVz\".rebates4()] +\"\"==\"MjAw\".reb" ascii
    $s2  = "var orange=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".rebates4())&&inferiority[\"c3RhdHVz\".rebates4()] +\"\"==\"MjAw\".reb" ascii
    $s3  = "monologue = \"_F2_\";" fullword ascii
    $s4  = "\"s\")+\"ubRt\"+(\"ordination\",\"disability\",\"bootless\",\"subheading\",\"nutrition\",\"grams\",\"narcissus\",\"ri\")+\"ng\")" ascii
    $s5  = "constraint = constraint+ washing.shift();" fullword ascii
    $s6  = "tumbler(\"aHR0cDovLw==\".rebates4()+\"\\u0073\\u0075\\u0062\\u0061\\u006E\\u0067\\u002E\\u0067\\u006F\\u002E\\u0069\"+\"\\u0064" ascii
    $s7  = "weasel = ((\"festivals\", \"ticklish\", \"extra\", \"faultless\", \"EuUeClmnu\") + \"yiPbTPTk\").rebates2();" fullword ascii
    $s8  = "String.prototype.rebates = function () {" fullword ascii
    $s9  = "String.prototype.rebates4 = function() {" fullword ascii
    $s10 = "String.prototype.rebates2 = function () {" fullword ascii
    $s11 = "var guest = washing.pop().split(\"" fullword ascii
    $s12 = "provisional = ((\"studies\", \"liberated\", \"leone\", \"eucalyptus\", \"sYPmcWVT\") + \"FUtKNLqXH\").rebates2();" fullword ascii
    $s13 = "var washing = [gingerly, politicians,brandishing,  \"\"+\".\"+(\"lying\",\"charge\",\"meetings\",\"expedia\",\"sepulture\",\"ext" ascii
    $s14 = "var zanzibar = new sluts(guest[1]);" fullword ascii
    $s15 = "var inspired = zanzibar[washing.shift()](washing.shift());" fullword ascii
    $s16 = "var gingerly = \"QWN0obliterateaXZlWE9iobliterateamVjdA==obliterate\".rebates4();" fullword ascii
    $s17 = "nless\",\"dictator\",\"reconsider\",\"likewise\",\"selfconscious\",\"08\"), provisional)] = 0;" fullword ascii
    $s18 = "function tumbler(sharpness, pincers) {" fullword ascii
    $s19 = "  bacteria = [];" fullword ascii
    $s20 = "outwards = this;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}