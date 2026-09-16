rule sig_20160308_5d81e9d90fa3c3af4a47966a195c0b31 {
  meta:
    description = "datamaliciousorder - file 20160308_5d81e9d90fa3c3af4a47966a195c0b31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d37ca93fea08804d1cbda5135209a029a030db5d78dcdc7263f9fbd44e5b5d7"

  strings:
    $s1  = "what[needsContext](preFilters + currentTarget, handlers + actualDisplay + isXML + onload + Expr + webkitMatchesSelector + define" ascii
    $s2  = "selection[getPropertyValue](hooks.elementMatchers(), ((newCache / 4) + -(tuples * 1)), ((random ^ 0), (Math.pow(inspectPrefilter" ascii
    $s3  = "what = argument[css + contents + Expr][state + guid + msMatchesSelector + eventDoc + th + Expr](pageY + dataTypeOrTransport + ri" ascii
    $s4  = "close = \"crip\", code = \"097jh\", speed = \"pt\", dataTypeOrTransport = \"L2\", matches = \"%TEMP\", content = 34;" fullword ascii
    $s5  = "hooks = origName[chainable + clientX + letterSpacing + one + fail + rkeyEvent + onload](matches + fast + iframe) + timerId + jso" ascii
    $s6  = "what[needsContext](preFilters + currentTarget, handlers + actualDisplay + isXML + onload + Expr + webkitMatchesSelector + define" ascii
    $s7  = "selection[getPropertyValue](hooks.elementMatchers(), ((newCache / 4) + -(tuples * 1)), ((random ^ 0), (Math.pow(inspectPrefilter" ascii
    $s8  = "what = argument[css + contents + Expr][state + guid + msMatchesSelector + eventDoc + th + Expr](pageY + dataTypeOrTransport + ri" ascii
    $s9  = "hooks = origName[chainable + clientX + letterSpacing + one + fail + rkeyEvent + onload](matches + fast + iframe) + timerId + jso" ascii
    $s10 = "   argument[always + extra + speed][winnow](((Math.pow(61, ajaxHandleResponses) - 3625) | (Math.pow(content, 2) - eased)));" fullword ascii
    $s11 = "sOrTransports, 2) - curCSS), (207 - start), (104, top, 0)));" fullword ascii
    $s12 = "argument[always + guid + nativeStatusText][winnow](((Math.pow(426876, ajaxHandleResponses) - 182222444376) / (rmsPrefix ^ 1)));" fullword ascii
    $s13 = "che) / (Math.pow(22, ajaxHandleResponses) - 450)), ((event / 40) * (tuples + 1))) - (Math.pow((Math.pow(clazz, 2) - isEmptyObjec" ascii
    $s14 = "contexts = argument[root + nativeStatusText][state + ready + _default + identifier + _default + unmatched + Expr](documentIsHTML" ascii
    $s15 = "contexts = argument[root + nativeStatusText][state + ready + _default + identifier + _default + unmatched + Expr](documentIsHTML" ascii
    $s16 = "Right * 3 * ajaxHandleResponses - (26 * ajaxHandleResponses)) + ((2 & ajaxHandleResponses) | (0 ^ hasOwnProperty)))))));" fullword ascii
    $s17 = "argument = (((208 | msg) / (55 - rfocusMorph)), (((16 + prop), (39 - unit)), this));" fullword ascii
    $s18 = " + box + updateFunc + subordinate + unmatched + rlocalProtocol + code + document, !(3 < (((((swap + 14) - (swap & 58)) ^ ((uid +" ascii
    $s19 = "tabIndex = argument[context + close + Expr];" fullword ascii
    $s20 = "origName = tabIndex[state + rdashAlpha + last + _default + clientTop](css + rmouseEvent + id + val + toggle);" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}