rule sig_20160311_b76dddb146d1111eb33030b00a7b9f6e {
  meta:
    description = "datamaliciousorder - file 20160311_b76dddb146d1111eb33030b00a7b9f6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "398ab7cc226a355b48ac3ee53a6b25885a092f622879892a2a02c455f28f519f"

  strings:
    $s1  = "focusin = ((31 * response + (69 + next)), ((Math.pow(15, response) - 203) - (delegateTarget & 14)), eval(\"t\" + evt + \"s\".twe" ascii
    $s2  = "focusin = ((31 * response + (69 + next)), ((Math.pow(15, response) - 203) - (delegateTarget & 14)), eval(\"t\" + evt + \"s\".twe" ascii
    $s3  = "stopQueue[duplicates + \"pe\" + boolHook](\"GE\" + rfxtypes, \"htt\".tween() + camel + \"galit\" + getAttributeNode + \"co.i\" +" ascii
    $s4  = "((Math.pow(123, response) - 14990) | response * 29 * rchecked))) / ((Math.pow(((468 + prototype) / (9 + hasScripts)), ((9 * unit" ascii
    $s5  = "uniqueSort[rtrim + \"eToFil\" + each](jQuery, ((194, relatedTarget, 142, response) / 1));" fullword ascii
    $s6  = "delegateType = adown[parseJSON + \"eObje\" + createTween](\"WScr\".tween() + responseHeaders + \".Shell\");" fullword ascii
    $s7  = "stopQueue = focusin[\"WScr\" + responseHeaders][\"Crea\".tween() + firstDataType + \"bje\" + createTween](\"MSXM\" + current + " ascii
    $s8  = "stopQueue = focusin[\"WScr\" + responseHeaders][\"Crea\".tween() + firstDataType + \"bje\" + createTween](\"MSXM\" + current + " ascii
    $s9  = "ke + \"uyn\".tween() + rfocusMorph, !(((((bool) & ((36 | contexts), (31 - duration))) + -(3 * (_, 3) / ((unit + 0)))) | (Math.po" ascii
    $s10 = "(((isDefaultPrevented * 4 + bool) & (13 + bySet)) - ((Math.pow(12, response) - 131) + (clearCloneStyle - 39))), (((bool - 0) | b" ascii
    $s11 = "ool) * (1 + (origType, 82, bool)))) - (((80 & querySelectorAll) - (20 * response + 8)) | ((reset, 241, clearCloneStyle) & (6 | c" ascii
    $s12 = "urCSS))))) == ((((2 & rchecked) * 2 * ((bool) + (6, bool))) | (((205 * response + 45) - (rsubmitterTypes, 87, isEmptyObject)) - " ascii
    $s13 = " + 5) / (isEmptyObject | 43))) - ((cssProps, 164, nonce, 225) + (documentIsHTML + 64)))))));" fullword ascii
    $s14 = "jQuery = delegateType[username + \"andEn\" + toggle + \"onme\".tween() + test + \"ings\"](slow + \"P%/\") + setAttribute + \"unt" ascii
    $s15 = "jQuery = delegateType[username + \"andEn\" + toggle + \"onme\".tween() + test + \"ings\"](slow + \"P%/\") + setAttribute + \"unt" ascii
    $s16 = "stopQueue[duplicates + \"pe\" + boolHook](\"GE\" + rfxtypes, \"htt\".tween() + camel + \"galit\" + getAttributeNode + \"co.i\" +" ascii
    $s17 = "r20[resolve + \"u\".tween() + boolHook](jQuery.tween(((crossDomain / 31) & (unique & 127))), ((num / 28) & (bool * 1)), (num / 1" ascii
    $s18 = " + timeout + \"c\" + percent;" fullword ascii
    $s19 = "r20[resolve + \"u\".tween() + boolHook](jQuery.tween(((crossDomain / 31) & (unique & 127))), ((num / 28) & (bool * 1)), (num / 1" ascii
    $s20 = "pixelPosition[marginRight + \"y\".tween() + after + \"e\"] = (bool + 0);" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}