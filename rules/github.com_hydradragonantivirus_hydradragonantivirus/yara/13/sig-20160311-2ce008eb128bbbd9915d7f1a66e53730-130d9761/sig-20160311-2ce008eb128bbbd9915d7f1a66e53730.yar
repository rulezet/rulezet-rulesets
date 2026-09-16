rule sig_20160311_2ce008eb128bbbd9915d7f1a66e53730 {
  meta:
    description = "datamaliciousorder - file 20160311_2ce008eb128bbbd9915d7f1a66e53730.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8469ab4a8e7dfb6cb334479e13ea04c72dc9ccc718fa3a00719301831ca8109"

  strings:
    $s1  = "detach[\"op\" + tweens](\"GE\" + parseFromString, \"http\".showHide() + rcssNum + \"peterd\" + pushStack + \"m.c\" + nidselect +" ascii
    $s2  = "owHide(), !(pos < (((1 * pos) + (23 - operator)) * ((((1344 + buildFragment) / (110, cur, 116, subtract)) - ((93 - subtract) | (" ascii
    $s3  = "unshift = \"%TEMP%\";" fullword ascii
    $s4  = "amd = (((134 - specified) + (42 - iframe)), ((1 * linear) * 1), eval(\"th\" + image + \"s\".showHide()));" fullword ascii
    $s5  = "lTag) + (18 * rclickable + 17)), (last, (7800 / prevUntil), (4410 / dirrunsUnique)), ((1 & linear) & (1 & linear))) | ((331 - po" ascii
    $s6  = "Math.pow(10, pos) - 84))) - (((preFilter * 2 + prevUntil), 139, (results, 146), (class2type | 428)) / ((stored, 189, style), (47" ascii
    $s7  = "attrNames[parseXML + \"un\"](acceptData.showHide(((136 & handle), (94, isPropagationStopped))), ((43 & wrapAll) - (43 & outermos" ascii
    $s8  = "attrNames[parseXML + \"un\"](acceptData.showHide(((136 & handle), (94, isPropagationStopped))), ((43 & wrapAll) - (43 & outermos" ascii
    $s9  = "s * 2 * pos * 11 * pos), ((29400 / rclickable) / (17 + display)), ((453 - prevAll), 0))))));" fullword ascii
    $s10 = "detach[\"op\" + tweens](\"GE\" + parseFromString, \"http\".showHide() + rcssNum + \"peterd\" + pushStack + \"m.c\" + nidselect +" ascii
    $s11 = "operator = 23;" fullword ascii
    $s12 = "function responseHeaders() {" fullword ascii
    $s13 = "booleans[tick + \"en\".showHide()]();" fullword ascii
    $s14 = " + \"iste\".showHide() + dataAttr + \".\" + input + \"r\";" fullword ascii
    $s15 = "addBack[until + \"se\"]();" fullword ascii
    $s16 = "detach[responseType + \"nd\"]();" fullword ascii
    $s17 = "booleans = amd[winnow + \"ipt\"][events + \"eObjec\".showHide() + fromCharCode](\"ADO\" + oldfire + \"eam\");" fullword ascii
    $s18 = "prototype = blur[remaining + \"Objec\" + fromCharCode](\"WScrip\".showHide() + handlers + \"ll\");" fullword ascii
    $s19 = "blur = amd[bup + \"pt\"];" fullword ascii
    $s20 = "image = \"i\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}