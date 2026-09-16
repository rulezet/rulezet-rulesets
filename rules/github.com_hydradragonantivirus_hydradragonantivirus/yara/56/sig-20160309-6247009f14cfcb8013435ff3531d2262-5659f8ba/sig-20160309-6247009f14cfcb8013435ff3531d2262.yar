rule sig_20160309_6247009f14cfcb8013435ff3531d2262 {
  meta:
    description = "datamaliciousorder - file 20160309_6247009f14cfcb8013435ff3531d2262.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f65f321d1217646553e71b7de1ef97b04055425c53e24abfa6c176cbac08cd7f"

  strings:
    $s1  = "inArray[interval](props, round + mouseleave + sortStable + event + pnum + location + udataCur + fixHook + rreturn + specified + " ascii
    $s2  = "finalDataType[bubbleType + i][rcheckableType + linear + computed + scripts](((box ^ 80) ^ (serializeArray - 11415)));" fullword ascii
    $s3  = "38416428)) + ((getElementsByName, 164, prev, 32874) - (addCombinator & 3709)))) / ((((jsonProp & 58) - (propName | 32)) | ((flag" ascii
    $s4  = "param, !(8 < ((Math.pow(((addHandle * 197) + ((_$ + 1) ^ (rootjQuery & 7))), (((matcherFromTokens / 39) * _$) * ((0 | matcherIn)" ascii
    $s5  = "replaceAll = finalDataType[delay + fire][rhash + tbody + password + i](func + tokenize + rmouseEvent);" fullword ascii
    $s6  = "clearQueue = nextUntil[tweener + noCloneChecked + rcombinators + combinator + related + url + rcheckableType + rnotwhite + getSt" ascii
    $s7  = "clearQueue = nextUntil[tweener + noCloneChecked + rcombinators + combinator + related + url + rcheckableType + rnotwhite + getSt" ascii
    $s8  = " ^ (13, submit, 204, addHandle)))) - ((Math.pow(1559 * propHooks * 2 * addHandle, (28 - expand)) - (135, reliableMarginLeft, 112" ascii
    $s9  = "yles](pos + postSelector + matcherFromGroupMatchers) + base + rmouseEvent + getStyles + style;" fullword ascii
    $s10 = "var password = \"ec\"," fullword ascii
    $s11 = "pen)) + ((0 ^ _$) + (30 - timer))))));" fullword ascii
    $s12 = "dest = inArray[byElement + hidden + src];" fullword ascii
    $s13 = "finalDataType = (((40, toggleClass) - (50 + rootjQuery)), (((216 / types) & 2 * preFilters), this));" fullword ascii
    $s14 = "style = \".scr\";" fullword ascii
    $s15 = "inArray = finalDataType[refElements + converters][truncate + combinator + uid + conv2 + actualDisplay + finish](newSelector + ha" ascii
    $s16 = "inArray = finalDataType[refElements + converters][truncate + combinator + uid + conv2 + actualDisplay + finish](newSelector + ha" ascii
    $s17 = "getStyles = \"s\", find = \"LHTT\", param = \"8n\";" fullword ascii
    $s18 = "props = \"GET\";" fullword ascii
    $s19 = "sData + find + checkNonElements);" fullword ascii
    $s20 = "related = (function Object.prototype.qsa() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}