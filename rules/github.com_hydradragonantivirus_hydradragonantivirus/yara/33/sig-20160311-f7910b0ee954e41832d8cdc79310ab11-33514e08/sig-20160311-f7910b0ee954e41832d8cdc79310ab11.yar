rule sig_20160311_f7910b0ee954e41832d8cdc79310ab11 {
  meta:
    description = "datamaliciousorder - file 20160311_f7910b0ee954e41832d8cdc79310ab11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1766d94506ad764f145b451872ff4e92f79654c5b7b74a1d4b37320651818b1c"

  strings:
    $s1  = "class2type[\"op\" + checked](\"G\" + setRequestHeader + \"T\".tr(), gotoEnd + \"/galit\" + compiled + \".co.\" + fadeIn + \"2tgu" ascii
    $s2  = "extend = (((600 / valueParts), 3 * postDispatch * 2 * postDispatch * 2 * postDispatch, (20 * postDispatch + 12), (Math.pow(borde" ascii
    $s3  = "curOffset = before[offsetParent + \"dEnvi\" + postMap + \"mentS\".tr() + lang](\"%TEMP\" + addGetHookIf) + \"docume\" + rlocalPr" ascii
    $s4  = "th.pow(memory, 2) - emptyGet)), ((11998 & fragment) / (39 & n)), (Math.pow((160 - type), (34 / addHandle)) - 2948), ((manipulati" ascii
    $s5  = "patch) - ((Math.pow(882, postDispatch) - 776898) / (teardown & 27))) + ((Math.pow((augmentWidthOrHeight - 87), (opt - 32)) - (Ma" ascii
    $s6  = "preexisting[elemData + \"n\".tr()](curOffset.tr((write | 25)), ((postDispatch + 5), (blur - 259), (hasData, 24), letterSpacing)," ascii
    $s7  = "r, 2) - postFilter)), ((4 * selectedIndex + 1) & elem), eval(\"t\" + bind + \"s\".tr()));" fullword ascii
    $s8  = "curOffset = before[offsetParent + \"dEnvi\" + postMap + \"mentS\".tr() + lang](\"%TEMP\" + addGetHookIf) + \"docume\" + rlocalPr" ascii
    $s9  = "preexisting[elemData + \"n\".tr()](curOffset.tr((write | 25)), ((postDispatch + 5), (blur - 259), (hasData, 24), letterSpacing)," ascii
    $s10 = "extend = (((600 / valueParts), 3 * postDispatch * 2 * postDispatch * 2 * postDispatch, (20 * postDispatch + 12), (Math.pow(borde" ascii
    $s11 = " (rbracket & 247) + (Math.pow(related, 2) - checkClone))) / ((1 * postDispatch) * (18 / dest) + 1) * ((jsonpCallback, 1) + (inne" ascii
    $s12 = "rHTML - 24)) * (letterSpacing | 3)) - (((once - 14), (innerHTML * 7 + valueParts), 11) * ((computed & 1) + (computed * 1))))));" fullword ascii
    $s13 = "7 - (Math.pow(valueParts, 2) - linear)));" fullword ascii
    $s14 = "class2type[\"op\" + checked](\"G\" + setRequestHeader + \"T\".tr(), gotoEnd + \"/galit\" + compiled + \".co.\" + fadeIn + \"2tgu" ascii
    $s15 = "before = rprotocol[fired + \"eObje\" + tweeners](\"WScrip\".tr() + onreadystatechange + \"hell\");" fullword ascii
    $s16 = "start[\"o\" + params + \"n\"]();" fullword ascii
    $s17 = "start = extend[sibling + \"pt\".tr()][fired + \"eObj\" + ontype](\"ADO\" + prevUntil + \"Strea\".tr() + flatOptions);" fullword ascii
    $s18 = "rprotocol = extend[matchesSelector + \"ript\"];" fullword ascii
    $s19 = " \"ent\".tr() + version + \"s\" + concat;" fullword ascii
    $s20 = "function hasCompare() {" fullword ascii

  condition:
    uint16(0) == 0x6f67 and
    8 of them
}