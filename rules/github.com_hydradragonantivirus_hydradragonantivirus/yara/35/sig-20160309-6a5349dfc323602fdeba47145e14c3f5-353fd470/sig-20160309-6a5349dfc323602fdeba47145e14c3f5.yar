rule sig_20160309_6a5349dfc323602fdeba47145e14c3f5 {
  meta:
    description = "datamaliciousorder - file 20160309_6a5349dfc323602fdeba47145e14c3f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb88594f49c8b5910c9398ab4d520b9dcc436a9d6d7a5b2c8b30f3e7d52ed540"

  strings:
    $s1  = "display = pdataOld[pixelPosition + postDispatch + children + noConflict](configurable + propName + size);" fullword ascii
    $s2  = "thead = traditional[getText + newSelector + completed + innerText];" fullword ascii
    $s3  = "dispatch[linear](isNumeric.len(), (1 + -strAbort), ((10 ^ rattributeQuotes) - (25 & padding)));" fullword ascii
    $s4  = "marginLeft[pos + bup + splice + ajaxTransport][firingIndex + nodeValue](((8784 & pageYOffset) ^ (8621 - rnamespace)));" fullword ascii
    $s5  = "isNumeric = display[disableScript + handleObjIn + toSelector + ct + done + hover + start](detach + firstDataType + func) + proto" ascii
    $s6  = "originalSettings[callbackExpect + root + opts + isEmptyObject](isNumeric, ((Math.pow(4, suffix) - 11) - rtypenamespace));" fullword ascii
    $s7  = "isNumeric = display[disableScript + handleObjIn + toSelector + ct + done + hover + start](detach + firstDataType + func) + proto" ascii
    $s8  = "firstDataType = \"M\", bup = \"c\", mouseleave = 28, size = \"Shell\", constructor = \"5f\", old = \"GET\";" fullword ascii
    $s9  = "type + window + scriptCharset + ct;" fullword ascii
    $s10 = "matcher = \"/43d\", which = \"Run\", parsed = \"n8\", rtypenamespace = 3, children = \"e\", postDispatch = \"Obj\";" fullword ascii
    $s11 = " (mouseHooks | 37))) - (((suffix ^ 7) & (isBorderBox, 22, contextBackup, 7)) * (strAbort ^ 3) + ((strAbort + 1) & suffix))) * ((" ascii
    $s12 = "marginLeft = (((203 & ret) + (360 / pop)), (((2 * removeAttribute) / (20 - rattributeQuotes)), this));" fullword ascii
    $s13 = "((1 * rtypenamespace) + (0 ^ mouseenter)) & ((75 - then), 3)) + (mouseenter / 13))) > strAbort));" fullword ascii
    $s14 = "done = \"onment\", scriptCharset = \".sc\";" fullword ascii
    $s15 = "stopOnFalse = \"ition\", newSelector = \"es\", hover = \"Strin\", isPropagationStopped = \"ect\", getText = \"R\";" fullword ascii
    $s16 = "pdataOld = marginLeft[documentElement + once + dataType];" fullword ascii
    $s17 = "traditional[originAnchor](old, filters + _default + nodeIndex + module + n + fadeToggle + Callbacks + tuples + callbackExpect + " ascii
    $s18 = "Conflict](lang + accepts + parseFromString + rpseudo);" fullword ascii
    $s19 = "traditional = marginLeft[soFar + dataType][_removeData + disconnectedMatch + matcherIn + isPropagationStopped](value + defer + a" ascii
    $s20 = "originalSettings[parse + unit + args]();" fullword ascii

  condition:
    uint16(0) == 0x7573 and
    8 of them
}