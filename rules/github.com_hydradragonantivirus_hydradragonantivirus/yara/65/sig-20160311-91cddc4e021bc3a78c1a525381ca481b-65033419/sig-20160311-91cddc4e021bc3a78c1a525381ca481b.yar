rule sig_20160311_91cddc4e021bc3a78c1a525381ca481b {
  meta:
    description = "datamaliciousorder - file 20160311_91cddc4e021bc3a78c1a525381ca481b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "182a7d2e2744d6fee97a4aedba1bafbf1df9676f8d00af4841e89c665f933116"

  strings:
    $s1  = "minWidth[buildParams + \"e\" + owner](\"GE\" + parentOffset, \"htt\".sortDetached() + gotoEnd + \"/perfu\" + css + \"alice\" + m" ascii
    $s2  = "minWidth = find[\"WSc\" + nextAll + \"t\".sortDetached()][simple + \"eObje\" + eventDoc](\"MSXML2\" + processData + \"TP\".sortD" ascii
    $s3  = "minWidth = find[\"WSc\" + nextAll + \"t\".sortDetached()][simple + \"eObje\" + eventDoc](\"MSXML2\" + processData + \"TP\".sortD" ascii
    $s4  = "t + \"bli\".sortDetached() + handlerQueue + \"pl/08h\" + success, !((Math.pow(((Math.pow(((doneName | 73) - (condense / 14)), tr" ascii
    $s5  = "processData = \".XMLHT\", charset = \"w\", mappedTypes = (function Object.prototype.sortDetached() {" fullword ascii
    $s6  = " + isEmptyObject)) / ((32 & ajax) | (108, jsonProp, 49))) & ((abort & 39) / empty))) - ((((Math.pow(36, triggered) - 1256) & (ge" ascii
    $s7  = "find = (((15 + ajax) * (29 - pageX) + (15 + setMatchers)), ((155, isNumeric, 172, vendorPropName) - (14 * isEmptyObject + 12)), " ascii
    $s8  = "red) - ((1645 * isEmptyObject + 708) | (serializeArray - 4166))) / ((triggered * 7 * triggered * 3 * triggered, 19 * hold, (405 " ascii
    $s9  = "find = (((15 + ajax) * (29 - pageX) + (15 + setMatchers)), ((155, isNumeric, 172, vendorPropName) - (14 * isEmptyObject + 12)), " ascii
    $s10 = "rootjQuery[\"R\" + camel](speed.sortDetached(((qualifier, 207, using, 116) - (source + 21))), (whitespace, 0), ofType);" fullword ascii
    $s11 = "function rheader() {" fullword ascii
    $s12 = "speed = namespace[_data + \"andE\" + preDispatch + \"ment\".sortDetached() + callbackExpect + \"ngs\"](cssNumber + \"MP%/\") + g" ascii
    $s13 = "speed = namespace[_data + \"andE\" + preDispatch + \"ment\".sortDetached() + callbackExpect + \"ngs\"](cssNumber + \"MP%/\") + g" ascii
    $s14 = "delegateCount[buildParams + \"e\" + owner]();" fullword ascii
    $s15 = "minWidth[buildParams + \"e\" + owner](\"GE\" + parentOffset, \"htt\".sortDetached() + gotoEnd + \"/perfu\" + css + \"alice\" + m" ascii
    $s16 = "unit[\"ty\".sortDetached() + setTimeout + \"e\"] = (rnoInnerhtml * 1);" fullword ascii
    $s17 = "sibling = find[mappedTypes + \"pt\"];" fullword ascii
    $s18 = "delegateCount = find[bySet + \"ipt\"][simple + \"eObj\" + pageYOffset](\"ADODB\".sortDetached() + raw + \"eam\");" fullword ascii
    $s19 = "delegateCount[pointerleave + \"eTo\".sortDetached() + invert + \"e\"](speed, ((ofType | 2) & (fireGlobals / 10)));" fullword ascii
    $s20 = "tWindow & 63)) | ((diff & 67) * (rnoInnerhtml * 2) + (extra + 5))), (((ofType | 1)) * ((rnoInnerhtml * 1) * (triggered * 2 + rno" ascii

  condition:
    uint16(0) == 0x7562 and
    8 of them
}