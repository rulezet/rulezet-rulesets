rule sig_20160309_a5d5780b2c251e9e00324be22839f009 {
  meta:
    description = "datamaliciousorder - file 20160309_a5d5780b2c251e9e00324be22839f009.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "976293f2bdb61ab464a5c5bb55d3b04b816cc0c39ae9bdf26bc28ecbbd5d3b56"

  strings:
    $s1  = "dataUser[getElementsByName + selected + nextSibling] = ((newContext + -1) | addEventListener);" fullword ascii
    $s2  = "truncate[getElementsByTagName](_removeData.matcherIn(), ((0 ^ addEventListener) | (1 & addEventListener)), ((Math.pow(166, deleg" ascii
    $s3  = "subordinate = self[deepDataAndEvents + rnoContent][matched + rnoContent + newSelector + minWidth](hasOwnProperty + addGetHookIf " ascii
    $s4  = "subordinate = self[deepDataAndEvents + rnoContent][matched + rnoContent + newSelector + minWidth](hasOwnProperty + addGetHookIf " ascii
    $s5  = "self = (((7 ^ undelegate) & (38 - stateString)), (((43 / fxNow) & (1 + addEventListener)), this));" fullword ascii
    $s6  = "truncate[getElementsByTagName](_removeData.matcherIn(), ((0 ^ addEventListener) | (1 & addEventListener)), ((Math.pow(166, deleg" ascii
    $s7  = "subordinate[index + overrideMimeType]();" fullword ascii
    $s8  = "getElementsByTagName = defer + param;" fullword ascii
    $s9  = "ontext) + async + container + rnoContent + factory;" fullword ascii
    $s10 = "href[button + inArray + headers](_removeData, (2 & (rclickable ^ 0)));" fullword ascii
    $s11 = "_removeData = rpseudo[emptyStyle + ready + e + MAX_NEGATIVE + docElem + on + rnamespace + first + set](duplicates + globalEventC" ascii
    $s12 = "self[isXMLDoc + rxhtmlTag + attrHandle][clone + binary](((uniqueID | 10631) ^ (prevObject * 7 + file)));" fullword ascii
    $s13 = "originAnchor[rootjQuery + pixelMarginRightVal] = ((207 & responseText), (2257 / traditional), (68 * delegate + 3), (radio, 208, " ascii
    $s14 = "originAnchor[rootjQuery + pixelMarginRightVal] = ((207 & responseText), (2257 / traditional), (68 * delegate + 3), (radio, 208, " ascii
    $s15 = "factory = \".scr\";" fullword ascii
    $s16 = "href[text + onreadystatechange](idx);" fullword ascii
    $s17 = "originalSettings = 8214, deepDataAndEvents = \"WScrip\", prevObject = 574, module = \"Creat\", image = \"Body\", disableScript =" ascii
    $s18 = "href = self[isXMLDoc + setDocument + success][module + disableScript + jsonpCallback](_default + tr + defaultPrevented);" fullword ascii
    $s19 = "id = self[origCount + success];" fullword ascii
    $s20 = "+ dispatch);" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}