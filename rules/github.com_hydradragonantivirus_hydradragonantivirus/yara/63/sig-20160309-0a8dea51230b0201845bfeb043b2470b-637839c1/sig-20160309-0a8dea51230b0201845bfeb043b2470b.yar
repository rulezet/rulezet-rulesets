rule sig_20160309_0a8dea51230b0201845bfeb043b2470b {
  meta:
    description = "datamaliciousorder - file 20160309_0a8dea51230b0201845bfeb043b2470b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462979334fbd23d3c07d425ebcb180c8e7266485c6e4935fceb8812f2e419617"

  strings:
    $x1  = "th[outermostContext + handlerQueue](rquery, scrollLeft + defaultDisplay + setMatched + rcheckableType + eventHandle + getBoundin" ascii
    $s2  = "gClientRect + doc + clazz + status + rcomma + rkeyEvent + unwrap + append + attrHandle, !(((((Math.pow((172, prefilterOrFactory," ascii
    $s3  = " 130), (pixelPositionVal ^ 3)) - (compile / 44)) ^ ((exports * 21 + originalEvent))), (Math.pow((36 - onlyHandlers) * (9 + curVa" ascii
    $s4  = "orig[getBoundingClientRect + high + parseOnly + rcomma]();" fullword ascii
    $s5  = "_default = aup[stopImmediatePropagation + checkDisplay + fnOver][cos + setRequestHeader + readyState + queue](timeStamp + conver" ascii
    $s6  = "vent)), ((0 | pixelPositionVal) * (29, actualDisplay, 2))) - (fadeOut * 2 * fadeOut * 2 * fadeOut * (3 ^ sortInput) + (Math.pow(" ascii
    $s7  = "splice = reliableMarginLeftVal[pdataOld + padding + swing + trim + rattributeQuotes + tabIndex + replaceAll](dequeue + doScroll)" ascii
    $s8  = "aup = (((39 * timeoutTimer + 31) ^ (support & 63)), (((Math.pow(capName, 2) - ownerDocument), (2 ^ map)), this));" fullword ascii
    $s9  = "ajax[setRequestHeader + finish] = ((225, map, 176, pixelPositionVal) ^ (1 * sortInput));" fullword ascii
    $s10 = "_default = aup[stopImmediatePropagation + checkDisplay + fnOver][cos + setRequestHeader + readyState + queue](timeStamp + conver" ascii
    $s11 = "reliableMarginLeftVal = PI[optDisabled + boxSizingReliable + fireWith + css + nodeValue](ajaxPrefilter + bind + siblings + attrs" ascii
    $s12 = "_default[statusText + setup + rcomma](splice, ((0 | fadeOut) & (1 * timeoutTimer)));" fullword ascii
    $s13 = "th = aup[to + fnOver][pseudo + readyState + queue](value + position + defaultView + swap);" fullword ascii
    $s14 = "splice = reliableMarginLeftVal[pdataOld + padding + swing + trim + rattributeQuotes + tabIndex + replaceAll](dequeue + doScroll)" ascii
    $s15 = "reliableMarginLeftVal = PI[optDisabled + boxSizingReliable + fireWith + css + nodeValue](ajaxPrefilter + bind + siblings + attrs" ascii
    $s16 = "buildFragment = 23, ajaxPrefilter = \"WScri\", support = 35, close = \"send\", swap = \"HTTP\", status = \"yst\";" fullword ascii
    $s17 = "tweeners = th[option + dataAndEvents + isArrayLike];" fullword ascii
    $s18 = "bind = \"pt.\";" fullword ascii
    $s19 = "compile = (function String.prototype.handler() {" fullword ascii
    $s20 = "th[close]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}