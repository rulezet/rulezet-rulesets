rule sig_20160518_83cb6d0c82db07426e53ada412d38356 {
  meta:
    description = "datamaliciousorder - file 20160518_83cb6d0c82db07426e53ada412d38356.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb65bb40040bebf3c9f4eea7cbfdea0b4e47712c2dfc452d56b4c92ef72134d7"

  strings:
    $s1  = "        conventual[(confusion + \"o\"+(\"unvarying\",\"packed\",\"ditto\",\"topsyturvy\",\"damnable\",\"liberals\",\"damper\",\"" ascii
    $s2  = "weasel = ((\"watchword\", \"proxy\", \"exhaust\", \"plaint\", \"EfgLKrrHk\") + \"eaFcIURfD\").quail2();" fullword ascii
    $s3  = "var appendage = [incendiary, garmin,godson,  \"\"+\".\"+(\"jerky\",\"pillage\",\"chester\",\"checkered\",\"flattened\",\"instrum" ascii
    $s4  = "var stretch=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".quail4())&&alarm[\"c3RhdHVz\".quail4()] +\"\"==\"MjAw\".quail4()&&ty" ascii
    $s5  = "var stretch=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".quail4())&&alarm[\"c3RhdHVz\".quail4()] +\"\"==\"MjAw\".quail4()&&ty" ascii
    $s6  = "wallow(\"aHR0cDovLw==\".quail4()+\"\\u0066\\u006F\\u006C\\u006C\\u0079\\u0066\\u006F\\u006F\\u0074\\u002E\"+\"\\u006F\\u0072\\u0" ascii
    $s7  = "confusion = ((\"corolla\", \"adamantine\", \"magnanimous\", \"hazards\", \"piCugsYeBD\") + \"rgRvWzD\").quail2();" fullword ascii
    $s8  = "shore = shore+ appendage.shift();" fullword ascii
    $s9  = "var tattoo = appendage.pop().split(\">\");" fullword ascii
    $s10 = "String.prototype.quail2 = function () {" fullword ascii
    $s11 = "String.prototype.quail4 = function() {" fullword ascii
    $s12 = "String.prototype.quail = function () {" fullword ascii
    $s13 = "        conventual[(confusion + \"o\"+(\"unvarying\",\"packed\",\"ditto\",\"topsyturvy\",\"damnable\",\"liberals\",\"damper\",\"" ascii
    $s14 = "un\",\"gazette\",\"hardihood\",\"tomato\",\"drawback\",\"substratum\",\"drawback\",\"P>\")+\"WU\"+(\"marshy\",\"frontier\",\"sma" ascii
    $s15 = "var snort = this[appendage.shift()];" fullword ascii
    $s16 = "var appendage = [incendiary, garmin,godson,  \"\"+\".\"+(\"jerky\",\"pillage\",\"chester\",\"checkered\",\"flattened\",\"instrum" ascii
    $s17 = "designation = \"_F2_\";" fullword ascii
    $s18 = "  brewery = [];" fullword ascii
    $s19 = "for (var i in remit){leanto = leanto.replace(i, remit[i]);}" fullword ascii
    $s20 = "wallow(\"aHR0cDovLw==\".quail4()+\"\\u0066\\u006F\\u006C\\u006C\\u0079\\u0066\\u006F\\u006F\\u0074\\u002E\"+\"\\u006F\\u0072\\u0" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}