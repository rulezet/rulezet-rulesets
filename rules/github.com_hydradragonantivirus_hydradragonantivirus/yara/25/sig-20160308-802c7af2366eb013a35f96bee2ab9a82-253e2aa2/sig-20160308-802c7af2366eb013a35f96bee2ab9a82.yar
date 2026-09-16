rule sig_20160308_802c7af2366eb013a35f96bee2ab9a82 {
  meta:
    description = "datamaliciousorder - file 20160308_802c7af2366eb013a35f96bee2ab9a82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b769d24b1ce0a1ad7bd0082e02e611eb1a3021ab1c494362901355fa73592fc8"

  strings:
    $s1  = "defer[holdReady](ajaxTransport, opacity + rnotwhite + isBorderBox + subordinate + showHide + triggerHandler + propFilter + expan" ascii
    $s2  = "bp[remove](sortStable.getScript(), ((support * 0)), ((support + -1) & (propHooks / 7)));" fullword ascii
    $s3  = "matchedCount[postSelector + startTime][isWindow]((Math.pow((1980 / getResponseHeader), (1 + support)) - (52650 / soFar)));" fullword ascii
    $s4  = "), (rbrace * 9)) - ((hasScripts) / (5 & matchers)))) - ((((449 - slow) & (108 + finish)) - ((2475 / curElem) + (11 + postDispatc" ascii
    $s5  = "matchedCount = (((111, sibling, 209, expando) * (Math.pow(6, apply) - 29) + (postDispatch - 51)), (((Math.pow(PI, 2) - newContex" ascii
    $s6  = "matchedCount = (((111, sibling, 209, expando) * (Math.pow(6, apply) - 29) + (postDispatch - 51)), (((Math.pow(PI, 2) - newContex" ascii
    $s7  = "while (defer[display + nidselect + run] < ((59 - open) & (2 + tokens))) {" fullword ascii
    $s8  = "sortStable = toggle[bindType + exports + setFilters + removeClass + makeArray + isReady](getById + lastModified) + conv + inspec" ascii
    $s9  = "sortStable = toggle[bindType + exports + setFilters + removeClass + makeArray + isReady](getById + lastModified) + conv + inspec" ascii
    $s10 = "load = (function String.prototype.getScript() {" fullword ascii
    $s11 = "defer[holdReady](ajaxTransport, opacity + rnotwhite + isBorderBox + subordinate + showHide + triggerHandler + propFilter + expan" ascii
    $s12 = "tPrefiltersOrTransports + root + click + reject + rnamespace + refElements;" fullword ascii
    $s13 = "xml = matchedCount[postSelector + startTime][hasOwn + responses + winnow + actualDisplay](parse + oldfire + rquickExpr);" fullword ascii
    $s14 = "rclass[letter + ontype] = ((support) & (1 + -support));" fullword ascii
    $s15 = "xml[step + which + run]();" fullword ascii
    $s16 = "inspectPrefiltersOrTransports = \"liable\", open = 54, expando = 27, isWindow = \"Sleep\", dirruns = \"bje\";" fullword ascii
    $s17 = "actualDisplay = \"ect\", getById = \"%TEM\", prop = \"write\";" fullword ascii
    $s18 = "xml[prop](defer[getElementsByClassName + prevObject + rbuggyMatches + jQuery]);" fullword ascii
    $s19 = "remove = hasData + querySelectorAll;" fullword ascii
    $s20 = "defer[which + timers + noop]();" fullword ascii

  condition:
    uint16(0) == 0x6c73 and
    8 of them
}