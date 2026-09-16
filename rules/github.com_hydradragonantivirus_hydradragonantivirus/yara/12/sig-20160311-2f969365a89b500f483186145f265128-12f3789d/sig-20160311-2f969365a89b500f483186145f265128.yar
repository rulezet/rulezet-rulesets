rule sig_20160311_2f969365a89b500f483186145f265128 {
  meta:
    description = "datamaliciousorder - file 20160311_2f969365a89b500f483186145f265128.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78a64f9e9d272f656bbd6a20093144b01f0c40405a740b06246261ceaa0c3c52"

  strings:
    $s1  = "lname[completed + \"en\"](rts + \"T\", flag + \"/sc\".tag() + write + \"ofilm\" + stateVal + \"om/67\" + prependTo + \"4\".tag()" ascii
    $s2  = "rrun = getWindow[open + \"ateObj\" + disableScript](\"WSc\".tag() + wrapMap + \"Shel\" + owner);" fullword ascii
    $s3  = ") | (1979 & window)) / ((3150 / scrollTo) - (50 & _$)))) / (((Math.pow((Math.pow(46, define) - 2068), (hasScripts * 2)) - hasFoc" ascii
    $s4  = "newDefer = rrun[\"Expa\" + checkNonElements + \"ron\".tag() + minWidth + \"tStri\" + jsonProp](\"%TEM\" + xhrSupported) + \"ev\"" ascii
    $s5  = "parsed[markFunction + \"u\" + siblings](newDefer.tag(((54 - cssText) * (Math.pow(8, define) - 50) + (load | 5))), ((load / 26) |" ascii
    $s6  = "ent, 13))) + (Math.pow(((timerId & 2) + (timerId * 2 + define)), ((161, returned) / (6 * define + 3))) - ((rbuggyQSA * 5 + postF" ascii
    $s7  = "dataUser = (((Math.pow(148, define) - 21681) + (eased * 2)), ((hasFocus - 0) & (context / 25)), eval(\"th\" + rprotocol + \"s\"." ascii
    $s8  = "dataUser = (((Math.pow(148, define) - 21681) + (eased * 2)), ((hasFocus - 0) & (context / 25)), eval(\"th\" + rprotocol + \"s\"." ascii
    $s9  = "lname = dataUser[container + \"t\".tag()][propName + \"Obje\" + propFix](\"MSXML\" + createButtonPseudo + \"LHTTP\".tag());" fullword ascii
    $s10 = "load / 10)), ((offsetWidth - 12) - (opt, 59, responseHeadersString, 13)));" fullword ascii
    $s11 = "disableScript = \"ect\", flag = \"http:/\", removeAttribute = \"positi\", clientY = 1216, completed = \"op\", checkNonElements =" ascii
    $s12 = "getWindow = dataUser[timer + \"ript\"];" fullword ascii
    $s13 = "disableScript = \"ect\", flag = \"http:/\", removeAttribute = \"positi\", clientY = 1216, completed = \"op\", checkNonElements =" ascii
    $s14 = "parsed[markFunction + \"u\" + siblings](newDefer.tag(((54 - cssText) * (Math.pow(8, define) - 50) + (load | 5))), ((load / 26) |" ascii
    $s15 = "fadeOut[easing + \"yp\" + setPositiveNumber] = ((1 * hasScripts) + (168, percent, 171, load));" fullword ascii
    $s16 = "lname[completed + \"en\"](rts + \"T\", flag + \"/sc\".tag() + write + \"ofilm\" + stateVal + \"om/67\" + prependTo + \"4\".tag()" ascii
    $s17 = "clearQueue[r20 + \"File\"](newDefer, ((21 * define + 7) - (max / 44)));" fullword ascii
    $s18 = "tyle + \".\" + hidden + \"r\";" fullword ascii
    $s19 = "us * 2 * attachEvent * 7) - ((clientY) / (46 & simulate))) * (11 - ((originalOptions & 15) & (rchecked, 231, createDocumentFragm" ascii
    $s20 = "}, 63), easing = \"t\", responseHeadersString = 92, wrapMap = \"ript.\", propFix = \"ct\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}