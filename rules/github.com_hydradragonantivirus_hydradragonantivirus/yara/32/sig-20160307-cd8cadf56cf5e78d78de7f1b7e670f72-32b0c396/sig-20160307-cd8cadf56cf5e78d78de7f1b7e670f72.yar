rule sig_20160307_cd8cadf56cf5e78d78de7f1b7e670f72 {
  meta:
    description = "datamaliciousorder - file 20160307_cd8cadf56cf5e78d78de7f1b7e670f72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8b69b9ba85aab8cf5a221cb1bbe0d96fb8afa399f6f368b94603bbc25768c6d"

  strings:
    $s1  = "keyHooks[assert + complete](dispatch + calculatePosition, fns + emptyGet + etag + qsa + oMatchesSelector + requestHeaders + orig" ascii
    $s2  = "while (keyHooks[addCombinator + truncate + check] < (5 * setGlobalEval * 2 * setGlobalEval * 2 / (Math.pow(styles, 2) - elementM" ascii
    $s3  = "while (keyHooks[addCombinator + truncate + check] < (5 * setGlobalEval * 2 * setGlobalEval * 2 / (Math.pow(styles, 2) - elementM" ascii
    $s4  = "setFilters = fxNow[createPositionalPseudo + hide + complete + display + fixHook + complete + simple + bySet + scrollTop](dataUse" ascii
    $s5  = "fxNow = div1[udataOld + which + srcElements + ap + matchIndexes](manipulationTarget + lastChild + statusCode + destElements + el" ascii
    $s6  = "fxNow = div1[udataOld + which + srcElements + ap + matchIndexes](manipulationTarget + lastChild + statusCode + destElements + el" ascii
    $s7  = "r + getPropertyValue + pointerleave + dataUser + tfoot) + namespace + simple + createFxNow + includeWidth;" fullword ascii
    $s8  = "keyHooks[assert + complete](dispatch + calculatePosition, fns + emptyGet + etag + qsa + oMatchesSelector + requestHeaders + orig" ascii
    $s9  = "    resolveWith[rheaders](keyHooks[seed + rnamespace + rchecked + overflowX + readyWait]);" fullword ascii
    $s10 = "inalEvent + getText + after + unshift, !(((((1 + fireGlobals) * (1 + fireGlobals)) * (((1 + fireGlobals) & (1 ^ fireGlobals)) * " ascii
    $s11 = "ajax = (((7740 / hidden) | (10150 / clientTop)), (((144 - responses) - (131 - events)), this));" fullword ascii
    $s12 = "    scale[username](setFilters.els(), ((1 * binary) * (29 - fadeIn)), (0, (binary + -1)));" fullword ascii
    $s13 = "keyHooks = ajax[preFilters + sort][realStringObj + extra + mozMatchesSelector + MAX_NEGATIVE + rwhitespace + Expr](offsetWidth +" ascii
    $s14 = "setFilters = fxNow[createPositionalPseudo + hide + complete + display + fixHook + complete + simple + bySet + scrollTop](dataUse" ascii
    $s15 = "keyHooks = ajax[preFilters + sort][realStringObj + extra + mozMatchesSelector + MAX_NEGATIVE + rwhitespace + Expr](offsetWidth +" ascii
    $s16 = "    ajax[preFilters + async + wait][implementation + load]((5 ^ fireGlobals) * 2 * setGlobalEval * (Math.pow(4, setGlobalEval) -" ascii
    $s17 = "    ajax[preFilters + async + wait][implementation + load]((5 ^ fireGlobals) * 2 * setGlobalEval * (Math.pow(4, setGlobalEval) -" ascii
    $s18 = "ajax[preFilters + sort][implementation + load](((options / 24)));" fullword ascii
    $s19 = "resolveWith = ajax[input + Expr][udataOld + winnow + write](stopImmediatePropagation + what + qualifier + lang);" fullword ascii
    $s20 = " needsContext + pseudo + modified + isXMLDoc);" fullword ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}