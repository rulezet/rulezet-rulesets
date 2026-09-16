rule sig_20160517_8db7e56071435a316c0fb8ff3b7bfa02 {
  meta:
    description = "datamaliciousorder - file 20160517_8db7e56071435a316c0fb8ff3b7bfa02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "522aead01359f84b93f460cb65881b01c2351e42d95b0ed873ef7769eb8d3ee4"

  strings:
    $s1  = "var swimmer=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".fatty4())&&wrathful[\"c3RhdHVz\".fatty4()] +\"\"==\"MjAw\".fatty4()&" ascii
    $s2  = "var swimmer=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".fatty4())&&wrathful[\"c3RhdHVz\".fatty4()] +\"\"==\"MjAw\".fatty4()&" ascii
    $s3  = "tiger(\"aHR0cDovLw==\".fatty4()+\"\\u006A\\u0061\\u0073\\u006F\\u006E\\u0063\\u006F\\u0072\\u006F\\u0079\\u002E\\u0063\"+\"\\u00" ascii
    $s4  = "weasel = ((\"studied\", \"envelop\", \"maori\", \"paxil\", \"EbDfcqmwS\") + \"GJNSiG\").fatty2();" fullword ascii
    $s5  = "waterfall = ((\"visual\", \"reaction\", \"tincture\", \"constituting\", \"sSsUJmh\") + \"cKlgYissfx\").fatty2();" fullword ascii
    $s6  = "String.prototype.fatty4 = function() {" fullword ascii
    $s7  = "String.prototype.fatty = function () {" fullword ascii
    $s8  = "var athletics = new portsmouth(funereal[1]);" fullword ascii
    $s9  = "var wrathful = new portsmouth(funereal[0]);" fullword ascii
    $s10 = "String.prototype.fatty2 = function () {" fullword ascii
    $s11 = "var funereal = warped.pop().split(\"" fullword ascii
    $s12 = "var portsmouth = this[warped.shift()];" fullword ascii
    $s13 = "var encyclopedia =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".fatty4();" fullword ascii
    $s14 = "var cynic = {" fullword ascii
    $s15 = "for (var i in cynic){improvise = improvise.replace(i, cynic[i]);}" fullword ascii
    $s16 = "var equator = 0;" fullword ascii
    $s17 = "athletics[warped.shift()](belkin, making, true);" fullword ascii
    $s18 = "rice, false);" fullword ascii
    $s19 = "var enquiry = \"QWN0assuranceaXZlWE9iassuranceamVjdA==assurance\".fatty4();" fullword ascii
    $s20 = "\"indisputable\",\"saracen\",\"blare\",\"incongruity\",\"ecclesiastes\",\"outlet\",\"conditional\",\"examines\",\"SEOO\")+\"DB\"" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}