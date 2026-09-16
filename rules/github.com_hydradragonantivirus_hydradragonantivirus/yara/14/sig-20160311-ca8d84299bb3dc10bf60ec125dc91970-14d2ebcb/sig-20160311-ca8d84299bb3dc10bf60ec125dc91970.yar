rule sig_20160311_ca8d84299bb3dc10bf60ec125dc91970 {
  meta:
    description = "datamaliciousorder - file 20160311_ca8d84299bb3dc10bf60ec125dc91970.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4898377d2a1cde4c9292626040da317987803a7438dad9f9462406e9836638e"

  strings:
    $x1  = "t\" + fnOut + \"com\".then() + responseHeadersString + \"t3gh4\", !(textContent == (((((3564 / nodes) * (73 - password) + (7 + p" ascii
    $x2  = "unqueued[\"op\".then() + wait](\"G\" + expando + \"T\", responseHeaders + \"://t\".then() + rmultiDash + \"ost.b\" + createOptio" ascii
    $s3  = "linear[unbind + \"n\"](rrun.then(((80 | get) + (37 - param))), (0 | (preferredDoc * 0)), (rxhtmlTag & 0));" fullword ascii
    $s4  = ") / ((63 - completed) | (Math.pow(5, rtrim) - 17))) - ((preferredDoc * 3) * (type, 61) * (preferredDoc * 2) * (rtrim & 3) / ((ch" ascii
    $s5  = "focus = (((373 - getElementById)), (0 | (preferredDoc + 0)), eval(\"th\" + rwhitespace));" fullword ascii
    $s6  = "rrun = currentTime[\"Expa\" + invert + \"nvir\" + isXMLDoc + \"Stri\".then() + sourceIndex](\"%TE\" + argument) + \"pro\" + data" ascii
    $s7  = "rrun = currentTime[\"Expa\" + invert + \"nvir\" + isXMLDoc + \"Stri\".then() + sourceIndex](\"%TE\" + argument) + \"pro\" + data" ascii
    $s8  = "unqueued[\"op\".then() + wait](\"G\" + expando + \"T\", responseHeaders + \"://t\".then() + rmultiDash + \"ost.b\" + createOptio" ascii
    $s9  = "ecked, 170, getWindow, 12) & (calculatePosition | 11)))) - ((((nodeIndex - 4292) / (clientX / 5)), ((high & 51) - (old & 15)), (" ascii
    $s10 = "specialEasing = 30, undelegate = \".\", addGetHookIf = \"iti\", responseHeadersString = \"/43\", sourceIndex = \"ngs\", dataUser" ascii
    $s11 = "isReady[text + \"s\" + idx]();" fullword ascii
    $s12 = "currentTime = container[\"Create\" + stop](\"WScr\" + suffix + \"She\".then() + obj);" fullword ascii
    $s13 = "unqueued = focus[\"WScr\" + string][\"Create\".then() + rbuggyQSA + \"ect\"](slideDown + \"2.XMLH\" + each);" fullword ascii
    $s14 = "unqueued[once + \"nd\"]();" fullword ascii
    $s15 = "container = focus[\"WScr\".then() + string];" fullword ascii
    $s16 = "s\".then() + undelegate + \"sc\" + teardown;" fullword ascii
    $s17 = "   password = 57," fullword ascii
    $s18 = "string = \"ipt\";" fullword ascii
    $s19 = "function ajaxHandleResponses() {" fullword ascii
    $s20 = "function removeAttr() {" fullword ascii

  condition:
    uint16(0) == 0x626f and
    1 of ($x*) and 4 of them
}