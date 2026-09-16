rule sig_20160311_ba94852cb6c65311b79dab8477e9bb7e {
  meta:
    description = "datamaliciousorder - file 20160311_ba94852cb6c65311b79dab8477e9bb7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2254249a8f83c129a8278c9e1a97cc4a3a98894949f309dc9a1e3d22af403f7"

  strings:
    $s1  = "realStringObj[rnoContent + \"pe\" + excess](\"GE\".iNoClone() + random, \"htt\" + progress + \"/galit\" + apply + \"o.il\".iNoCl" ascii
    $s2  = "defaultExtra[argument + \"n\"](offsetWidth.iNoClone((2, setOffset, 89)), combinator, ((47 & contentType) - (23 * defineProperty " ascii
    $s3  = ") - (Math.pow(35, defineProperty) - 1178)) + ((detach, 229, getElementsByName, 1) * ignored))))));" fullword ascii
    $s4  = "defaultExtra[argument + \"n\"](offsetWidth.iNoClone((2, setOffset, 89)), combinator, ((47 & contentType) - (23 * defineProperty " ascii
    $s5  = "checkNonElements = uniqueID[state + \"ipt\"][getText + \"eObj\" + elements](\"ADOD\".iNoClone() + readyState + \"am\");" fullword ascii
    $s6  = "tween = \"%TEMP%\";" fullword ascii
    $s7  = "uniqueID = ((Math.pow((29 * defineProperty + 6), (unmatched, 133, defineProperty)) - 2 * when * 2 * mappedTypes * 3), ((Math.pow" ascii
    $s8  = "uniqueID = ((Math.pow((29 * defineProperty + 6), (unmatched, 133, defineProperty)) - 2 * when * 2 * mappedTypes * 3), ((Math.pow" ascii
    $s9  = "p + \"tguyn\" + inspect, !(5 < ((((mapped - 51) & (combinator | 2)) & (((ignored & 1) | (combinator / 41)) * ((pattern & 253), (" ascii
    $s10 = "realStringObj[rnoContent + \"pe\" + excess](\"GE\".iNoClone() + random, \"htt\" + progress + \"/galit\" + apply + \"o.il\".iNoCl" ascii
    $s11 = "fragment[\"ty\".iNoClone() + locked + \"e\"] = ((163 - status), 207, ignored);" fullword ascii
    $s12 = "tElementsByName - 14)))) + (((defineProperty * 2 * defineProperty * 2 * defineProperty) - ((12 + eventDoc))) * (((1550 / checked" ascii
    $s13 = "(select, 2) - ofType) | (2 * select)), eval(\"t\" + map + \"s\".iNoClone()));" fullword ascii
    $s14 = "realStringObj = uniqueID[state + \"ipt\"][pageY + \"teObje\" + isReady](\"MSXML2\".iNoClone() + ajaxSettings + \"TTP\");" fullword ascii
    $s15 = "offsetWidth = tokenCache[visible + \"andEnv\".iNoClone() + truncate + \"mentS\" + matcherFromTokens + \"s\"](tween + \"/\".iNoCl" ascii
    $s16 = "offsetWidth = tokenCache[visible + \"andEnv\".iNoClone() + truncate + \"mentS\" + matcherFromTokens + \"s\"](tween + \"/\".iNoCl" ascii
    $s17 = "contentType = (function String.prototype.iNoClone() {" fullword ascii
    $s18 = "view = uniqueID[style + \"rip\" + uniqueSort];" fullword ascii
    $s19 = "checkNonElements[hooks + \"e\" + excess]();" fullword ascii
    $s20 = "realStringObj[\"se\" + excess + \"d\".iNoClone()]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}