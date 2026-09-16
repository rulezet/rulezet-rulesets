rule sig_20160516_8cd2838173237a89b70a6c81b1da0eb1 {
  meta:
    description = "datamaliciousorder - file 20160516_8cd2838173237a89b70a6c81b1da0eb1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "032c295c741f9187c54f9b1928eabcb6d3a4f429be03119d772846f9ccdcafc1"

  strings:
    $s1  = "var tolerance = [baldness, spectrum,flirtation,  \"\"+\".\"+(\"unabated\",\"temps\",\"austria\",\"commit\",\"fervor\",\"scapegra" ascii
    $s2  = "weasel = ((\"whether\", \"astronomer\", \"usher\", \"playstation\", \"EACYUhhkwd\") + \"iUUvqtTRJ\").bolting2();" fullword ascii
    $s3  = "        ceres[(snail + \"o\"+(\"tinkling\",\"chrysler\",\"bethany\",\"quizzical\",\"loaded\",\"assume\",\"mitigate\",\"genesis\"" ascii
    $s4  = "paddling(\"aHR0cDovLw==\".bolting4()+\"\\u0069\\u006D\\u0061\\u0067\\u0069\\u006E\\u0061\\u002D\\u0065\\u0073\\u002E\"+\"\\u0063" ascii
    $s5  = "terrestrial = terrestrial+ tolerance.shift();" fullword ascii
    $s6  = "var tolerance = [baldness, spectrum,flirtation,  \"\"+\".\"+(\"unabated\",\"temps\",\"austria\",\"commit\",\"fervor\",\"scapegra" ascii
    $s7  = "String.prototype.bolting2 = function () {" fullword ascii
    $s8  = "String.prototype.bolting = function () {" fullword ascii
    $s9  = "snail = ((\"forthcoming\", \"tithe\", \"deviation\", \"directive\", \"pYfsIRwCaK\") + \"mtoTlLje\").bolting2();" fullword ascii
    $s10 = "String.prototype.bolting4 = function() {" fullword ascii
    $s11 = "s\")+\"ubRt\"+(\"oasis\",\"thrall\",\"physicians\",\"cricket\",\"collectibles\",\"opinions\",\"stuffing\",\"ri\")+\"ng\").replac" ascii
    $s12 = "        var ceres = new anomalous(((\"singularity\",\"atheism\",\"descriptive\",\"invalid\",\"meanwhile\",\"lapel\",\"gathering" ascii
    $s13 = "        var ceres = new anomalous(((\"singularity\",\"atheism\",\"descriptive\",\"invalid\",\"meanwhile\",\"lapel\",\"gathering" ascii
    $s14 = "sikkim = this;" fullword ascii
    $s15 = "seller, false);" fullword ascii
    $s16 = "var disappointing = new anomalous(terminals[1]);" fullword ascii
    $s17 = "var baldness = \"QWN0aXZlWE9iamVjdA==\".bolting4();" fullword ascii
    $s18 = "var nvidia = new anomalous(terminals[0]);" fullword ascii
    $s19 = "var hoist = {" fullword ascii
    $s20 = "  socialism = [];" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}