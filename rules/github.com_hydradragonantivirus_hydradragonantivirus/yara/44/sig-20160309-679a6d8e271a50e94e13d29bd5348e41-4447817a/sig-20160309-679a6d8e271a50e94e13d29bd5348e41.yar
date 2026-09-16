rule sig_20160309_679a6d8e271a50e94e13d29bd5348e41 {
  meta:
    description = "datamaliciousorder - file 20160309_679a6d8e271a50e94e13d29bd5348e41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff2bc501a08a8ec5056ccdc8da3071f7d764aeef46628770d09295fce4eba3c5"

  strings:
    $s1  = "forward = (((16 | el), (8 * elems), (58 + relative)), (((1 + isReady) * (17 - closest)), this));" fullword ascii
    $s2  = "selectors[swing](crossDomain, rclickable + parentNode + postFinder + caption + when + overflowY + run + cssShow + speed + styles" ascii
    $s3  = "charset = selectors[noop + last + opts + targets];" fullword ascii
    $s4  = " + before + setter, !(5 < (((deep | (3 + isReady)) & ((5 + deep) & (Math.pow(6, deep) - 29))) ^ (((round | 18) / (Math.pow(setup" ascii
    $s5  = "rquery = \"X\", rootjQuery = (function String.prototype.delegateTarget() {" fullword ascii
    $s6  = "contentDocument[complete + optionSet](charset);" fullword ascii
    $s7  = "input = acceptData[start + hasContent + overflowX + bind + rhtml + createDocumentFragment](conv + fixHooks) + source + width + f" ascii
    $s8  = "contentDocument = forward[t + disable + beforeunload + then][defaultPrefilter + hold + colgroup](pushStack + rootjQuery + curTop" ascii
    $s9  = "contentDocument = forward[t + disable + beforeunload + then][defaultPrefilter + hold + colgroup](pushStack + rootjQuery + curTop" ascii
    $s10 = "input = acceptData[start + hasContent + overflowX + bind + rhtml + createDocumentFragment](conv + fixHooks) + source + width + f" ascii
    $s11 = "window[showHide] = ((isReady + 0) | (_queueHooks, 62, hasCompare, 0));" fullword ascii
    $s12 = "contentDocument[event + letter](input, ((177, tag, 251, ap), (2 & duration)));" fullword ascii
    $s13 = "selectors = forward[rbuggyMatches + beforeunload + then][initial + props + colgroup](matchIndexes + undelegate + rquery + remain" ascii
    $s14 = "abort = forward[fixHook + filter + rprotocol];" fullword ascii
    $s15 = "forward[lastChild + timers + then][replaceAll]((2 * _queueHooks * 2 * deep | (16026 & clientX)));" fullword ascii
    $s16 = "selectors = forward[rbuggyMatches + beforeunload + then][initial + props + colgroup](matchIndexes + undelegate + rquery + remain" ascii
    $s17 = "acceptData = abort[defaultPrefilter + fontWeight + using + colgroup](t + hidden + then + m + dataType);" fullword ascii
    $s18 = ", 2) - siblingCheck)) / ((1 ^ duration) & 3)))));" fullword ascii
    $s19 = "prevAll[rinputs + minWidth] = ((handler - 35) & removeAttribute);" fullword ascii
    $s20 = "selectors[swing](crossDomain, rclickable + parentNode + postFinder + caption + when + overflowY + run + cssShow + speed + styles" ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}