rule sig_20160516_7a0532b82c1487cc99188d750233b2d2 {
  meta:
    description = "datamaliciousorder - file 20160516_7a0532b82c1487cc99188d750233b2d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32fdccbb2ac74c15700d5f8c6223b5cbb772a8f55a5197e4e9f0fcf1276c1ab0"

  strings:
    $s1  = "portrait = ((\"bedtime\", \"earthquake\", \"portraits\", \"oxide\", \"pgwSrfM\") + \"LupKSNze\").quaff2();" fullword ascii
    $s2  = "var glutton=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".quaff4())&&crusade[\"c3RhdHVz\".quaff4()] +\"\"==\"MjAw\".quaff4()&&" ascii
    $s3  = "        var wellington = new warcraft(((\"thwart\",\"barometer\",\"huntington\",\"gently\",\"hostel\",\"didactic\",\"blindfold\"" ascii
    $s4  = "var glutton=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".quaff4())&&crusade[\"c3RhdHVz\".quaff4()] +\"\"==\"MjAw\".quaff4()&&" ascii
    $s5  = "abridgment(\"aHR0cDovLw==\".quaff4()+\"\\u006D\\u0072\\u0032\\u0070\\u0065\\u0074\\u0065\\u0072\\u002E\\u0064\"+\"\\u0065\\u002F" ascii
    $s6  = "weasel = ((\"leprosy\", \"irrational\", \"violin\", \"arroyo\", \"EPtNUpsMbMT\") + \"OTYqgo\").quaff2();" fullword ascii
    $s7  = "            crusade[trite]((\"lavishly\",\"publishing\",\"G\" + weasel) + (\"trolley\",\"pinnacle\",\"astrologer\",\"armory\",\"" ascii
    $s8  = "            crusade[trite]((\"lavishly\",\"publishing\",\"G\" + weasel) + (\"trolley\",\"pinnacle\",\"astrologer\",\"armory\",\"" ascii
    $s9  = "String.prototype.quaff4 = function() {" fullword ascii
    $s10 = "var combat = \"QWN0aXZlWE9iamVjdA==\".quaff4();" fullword ascii
    $s11 = "String.prototype.quaff2 = function () {" fullword ascii
    $s12 = "String.prototype.quaff = function () {" fullword ascii
    $s13 = "var heredity = webshots.pop().split(\"" fullword ascii
    $s14 = "var webshots = [combat, vulcan,baseless,  \"\"+\".\"+(\"lightbox\",\"rockies\",\"parvenu\",\"surfaces\",\"global\",\"requiring\"" ascii
    $s15 = "var webshots = [combat, vulcan,baseless,  \"\"+\".\"+(\"lightbox\",\"rockies\",\"parvenu\",\"surfaces\",\"global\",\"requiring\"" ascii
    $s16 = "        wellington[(portrait + \"o\"+(\"fresh\",\"bring\",\"mozambique\",\"serve\",\"nurse\",\"looped\",\"banjo\",\"escorts\",\"" ascii
    $s17 = "        wellington[(portrait + \"o\"+(\"fresh\",\"bring\",\"mozambique\",\"serve\",\"nurse\",\"looped\",\"banjo\",\"escorts\",\"" ascii
    $s18 = "var concept = pointing[webshots.shift()](webshots.shift());" fullword ascii
    $s19 = "var baseless =\"JVRFTVAl\".quaff4();" fullword ascii
    $s20 = "        var wellington = new warcraft(((\"thwart\",\"barometer\",\"huntington\",\"gently\",\"hostel\",\"didactic\",\"blindfold\"" ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}