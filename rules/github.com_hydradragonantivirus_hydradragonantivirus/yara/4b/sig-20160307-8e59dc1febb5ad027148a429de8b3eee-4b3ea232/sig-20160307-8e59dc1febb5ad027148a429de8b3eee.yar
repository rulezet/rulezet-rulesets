rule sig_20160307_8e59dc1febb5ad027148a429de8b3eee {
  meta:
    description = "datamaliciousorder - file 20160307_8e59dc1febb5ad027148a429de8b3eee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da01b4f3df1b4fd4dc14c435e97362c524bf68ffcd57843b070b35a25e9a2274"

  strings:
    $s1  = "rclickable[doneName](serialize, qsaError + traditional + tuple + rejectWith + optDisabled + identifier + handleObj + simulate + " ascii
    $s2  = "133, unit, 64, outermost))) | (Math.pow(((700 - modified) - (7056 / currentTime)), (1 + (hookFn, 154, jsonProp))) - ((142169 - e" ascii
    $s3  = "rclickable[doneName](serialize, qsaError + traditional + tuple + rejectWith + optDisabled + identifier + handleObj + simulate + " ascii
    $s4  = "isXMLDoc = (((41 - escaped) + (145 ^ startTime)), (((49 & curCSSTop) - (21 + addGetHookIf)), this));" fullword ascii
    $s5  = " source[deep + e] = ((addGetHookIf - 9) & (rclass ^ 0));" fullword ascii
    $s6  = "rclickable[getAttribute + rsubmitterTypes + each]();" fullword ascii
    $s7  = "outermost = 23, hasScripts = \"eam\", nodeValue = \"M\", clientTop = \"se\", createComment = 21, deep = \"positi\";" fullword ascii
    $s8  = " isXMLDoc[globalEval + originalProperties + ap][camelKey + rsubmitterTypes + postFinder](((30 & outermost) * (2 ^ removeEventLis" ascii
    $s9  = "isXMLDoc[obj + getResponseHeader + preDispatch][rmargin + isArrayLike](((215208 / isLocal) * (2 & fireGlobals) + (228096 / match" ascii
    $s10 = " isXMLDoc[globalEval + originalProperties + ap][camelKey + rsubmitterTypes + postFinder](((30 & outermost) * (2 ^ removeEventLis" ascii
    $s11 = "while (rclickable[contains + getAttribute + preDispatch + selection] < ((23 & createComment), (62 + rbrace), (4 + rclass))) {" fullword ascii
    $s12 = "isXMLDoc[obj + getResponseHeader + preDispatch][rmargin + isArrayLike](((215208 / isLocal) * (2 & fireGlobals) + (228096 / match" ascii
    $s13 = "rclickable = isXMLDoc[excess + complete + preDispatch][using + computeStyleTests + second + andSelf](nodeValue + when + origType" ascii
    $s14 = "rclickable = isXMLDoc[excess + complete + preDispatch][using + computeStyleTests + second + andSelf](nodeValue + when + origType" ascii
    $s15 = "teardown = \".scr\";" fullword ascii
    $s16 = "ajaxTransport = markFunction[num + parseXML + dequeue + curTop](cssFn + tr + sort);" fullword ascii
    $s17 = "disableScript = \"i\", opacity = \"ADOD\";" fullword ascii
    $s18 = "noCloneChecked = isXMLDoc[rfocusable + checkNonElements + indirect][showHide + tweener + cached + preDispatch](opacity + swap + " ascii
    $s19 = "needsContext = 144, serialize = \"GET\", currentTime = 49, cssFn = \"WScri\", originalOptions = \"MP%/\";" fullword ascii
    $s20 = "timers = \"saveTo\", getResponseHeader = \"ip\", globalEval = \"WS\", unit = 241, doneName = \"open\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}