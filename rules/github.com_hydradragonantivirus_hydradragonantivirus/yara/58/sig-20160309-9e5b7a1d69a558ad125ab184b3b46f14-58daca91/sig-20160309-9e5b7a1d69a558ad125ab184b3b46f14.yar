rule sig_20160309_9e5b7a1d69a558ad125ab184b3b46f14 {
  meta:
    description = "datamaliciousorder - file 20160309_9e5b7a1d69a558ad125ab184b3b46f14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75077efff4c649602e1dd0b035e24b16745e0815b2743df2fde94aeca595044b"

  strings:
    $s1  = "preMap[stopQueue](urlAnchor + tweener, createComment + obj + pointerleave + dir + preventDefault + argument + insertBefore + rpa" ascii
    $s2  = "getClientRects = ((Math.pow((Math.pow(93, funcName) - 8540), funcName) - (1157 | configurable)), (((45 - propFilter) / (30 & ins" ascii
    $s3  = "Name | (561 / overflowX)), (Math.pow(2 * isImmediatePropagationStopped * 2, (postFilter, 168, funcName)) - (26396 - wrapMap)), (" ascii
    $s4  = "values = getClientRects[nodeNameSelector + closest][hasScripts + multipleContexts + always + fn](remove + size + bySet + duratio" ascii
    $s5  = "values = getClientRects[nodeNameSelector + closest][hasScripts + multipleContexts + always + fn](remove + size + bySet + duratio" ascii
    $s6  = "preMap = getClientRects[undelegate + td + oldCache][postSelector + run + p + string + fix + _queueHooks](compiled + Deferred + a" ascii
    $s7  = "preMap = getClientRects[undelegate + td + oldCache][postSelector + run + p + string + fix + _queueHooks](compiled + Deferred + a" ascii
    $s8  = "prefix[realStringObj] = ((5 * offsetHeight + 1) / (rattributeQuotes * 6 + scripts));" fullword ascii
    $s9  = "fadeToggle[ajaxSettings + send + mouseenter] = ((0 / noGlobal) | (1 * postFilter));" fullword ascii
    $s10 = "getClientRects[active + _queueHooks][size + conv + eventPath](((related * 2 + rinputs) ^ (1175 | prop)));" fullword ascii
    $s11 = "excess = pageXOffset[doneName + createPositionalPseudo + evt + selectors + node + newUnmatched](buildFragment + getJSON) + cors " ascii
    $s12 = "preventDefault = \".w\", td = \"Scri\", string = \"b\", createComment = \"http\", run = \"at\";" fullword ascii
    $s13 = "excess = pageXOffset[doneName + createPositionalPseudo + evt + selectors + node + newUnmatched](buildFragment + getJSON) + cors " ascii
    $s14 = "ddToPrefiltersOrTransports + simple);" fullword ascii
    $s15 = "preMap[stopQueue](urlAnchor + tweener, createComment + obj + pointerleave + dir + preventDefault + argument + insertBefore + rpa" ascii
    $s16 = "values[removeAttr + compile + conv](excess, 2);" fullword ascii
    $s17 = "fix = \"jec\", qualifier = \"xes\", always = \"j\", postSelector = \"Cre\", bySet = \"trea\", doneName = \"Expand\";" fullword ascii
    $s18 = "active = (function String.prototype.getAttribute() {" fullword ascii
    $s19 = "+ doScroll + qualifier + marginDiv;" fullword ascii
    $s20 = "rentsprev + preDispatch + parents + rmargin + stopPropagation, !(7 == ((((nidselect & 2) * (rtagName / 2), (funcName * 41 * func" ascii

  condition:
    uint16(0) == 0x7263 and
    8 of them
}