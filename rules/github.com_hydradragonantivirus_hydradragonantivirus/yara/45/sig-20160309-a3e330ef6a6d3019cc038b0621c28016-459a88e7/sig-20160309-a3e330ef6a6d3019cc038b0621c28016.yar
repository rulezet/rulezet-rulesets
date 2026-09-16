rule sig_20160309_a3e330ef6a6d3019cc038b0621c28016 {
  meta:
    description = "datamaliciousorder - file 20160309_a3e330ef6a6d3019cc038b0621c28016.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d714226d2d52d2dd8f8614d822eaa55c873e96fd50758a506b28c38fe50b5862"

  strings:
    $s1  = "done = selector[size + get + map](copyIsArray + createTween + rclickable + getScript + getScript);" fullword ascii
    $s2  = "animated = parsed[animation + preferredDoc + getComputedStyle];" fullword ascii
    $s3  = "JSON[buildFragment + cssNumber][token + async]((setTimeout * 2 ^ elems * 2 * getBoundingClientRect));" fullword ascii
    $s4  = "dataUser[ontype](matchedCount.timeStamp(), ((1 & name) + -1), ((pop & 0)));" fullword ascii
    $s5  = "token = \"Sl\", traditional = \"pt\", thead = \"ML\", unloadHandler = 3, getComputedStyle = \"dy\";" fullword ascii
    $s6  = "parsed[script + ap]();" fullword ascii
    $s7  = "parsed[htmlPrefilter](split, dirruns + preFilter + trim + newCache + mimeType + originAnchor + unshift + special, !((((((110, ti" ascii
    $s8  = "matchedCount = done[isNumeric + isXMLDoc + newUnmatched + setRequestHeader + checkOn + namespaces + actualDisplay](tweener + win" ascii
    $s9  = " rbrace) - 1109))), ((((name & 1) + -(name * 1)) & ((name) * (1 + pop))) | (((2 * unloadHandler) | (1 + w)) + ((2 * elems) + 0))" ascii
    $s10 = "parsed = JSON[rchecked + tabIndex + traditional][getClass + current + cssProps](destElements + $ + thead + wrapAll);" fullword ascii
    $s11 = "matchedCount = done[isNumeric + isXMLDoc + newUnmatched + setRequestHeader + checkOn + namespaces + actualDisplay](tweener + win" ascii
    $s12 = "timeoutTimer[docElem + adjusted + state + ct + swing](matchedCount, ((toSelector - 35) & (fontWeight, 3)));" fullword ascii
    $s13 = "atchers + grep + identifier);" fullword ascii
    $s14 = "timeoutTimer = JSON[buildFragment + result + rquickExpr][mouseleave + minWidth + matchesSelector + rquickExpr](matcherFromGroupM" ascii
    $s15 = "timeoutTimer[webkitMatchesSelector + tabIndex + defaultExtra](animated);" fullword ascii
    $s16 = "preventDefault = \"ition\", script = \"sen\";" fullword ascii
    $s17 = "split = \"GET\";" fullword ascii
    $s18 = "setRequestHeader = \"vironm\", special = \"j\", isXMLDoc = \"nd\";" fullword ascii
    $s19 = "selector = JSON[copyIsArray + hookFn];" fullword ascii
    $s20 = "unqueued[attributes + actualDisplay + preventDefault] = ((close, 166, boxSizingReliableVal, 0) | (name * 0));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}