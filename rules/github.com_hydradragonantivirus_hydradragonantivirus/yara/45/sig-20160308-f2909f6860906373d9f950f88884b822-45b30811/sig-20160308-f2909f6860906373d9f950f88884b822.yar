rule sig_20160308_f2909f6860906373d9f950f88884b822 {
  meta:
    description = "datamaliciousorder - file 20160308_f2909f6860906373d9f950f88884b822.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "267081e21c699e1abb7cc0124985d5d0e71f72bdb05cf4c26611459dfb282715"

  strings:
    $x1  = "rdisplayswap[now](random, noBubble + matchers + origCount + rquery + global + password + restoreScript + scale + toSelector + da" ascii
    $s2  = "taUser + targets, !(relative < (((((327 * getElementsByTagName + 182) - (trim + 638)) / ((firing & 15) + (mapped - 43))) / (((cl" ascii
    $s3  = " siblingCheck)) | ((288 | relatedTarget) - (110, keys, 168))), (attrHandle * 3 | (Math.pow(relative, 2) - oldCallbacks)) * ((38," ascii
    $s4  = "Expr[proxy + clearCloneStyle + replaceChild + events][thead + b](((unshift) + (24715 - conv)));" fullword ascii
    $s5  = "while (rdisplayswap[setGlobalEval + readyWait + createPositionalPseudo] < (Math.pow((1 | attrHandle), (2 + evt)) - (5 & original" ascii
    $s6  = "rdisplayswap[now](random, noBubble + matchers + origCount + rquery + global + password + restoreScript + scale + toSelector + da" ascii
    $s7  = "while (rdisplayswap[setGlobalEval + readyWait + createPositionalPseudo] < (Math.pow((1 | attrHandle), (2 + evt)) - (5 & original" ascii
    $s8  = "combinator = defaultPrevented[toggleClass + next + cssText + rmsPrefix + _data + contentType + parseHTML + doAnimation](margin +" ascii
    $s9  = "one + 65), (isArrayLike, 208, conditionFn, 57), (cssFn | 4)) ^ (evt | 0))) ^ ((((reliableMarginRight ^ 2) & (Math.pow(prop, 2) -" ascii
    $s10 = "rdisplayswap = Expr[attrHooks + idx + _jQuery][rscriptType + num + rmouseEvent + fast](curValue + implementation + mouseleave + " ascii
    $s11 = "targets = \"hg\", now = \"open\", winnow = \"write\", cloneNode = \"WScri\";" fullword ascii
    $s12 = "rdisplayswap = Expr[attrHooks + idx + _jQuery][rscriptType + num + rmouseEvent + fast](curValue + implementation + mouseleave + " ascii
    $s13 = "combinator = defaultPrevented[toggleClass + next + cssText + rmsPrefix + _data + contentType + parseHTML + doAnimation](margin +" ascii
    $s14 = "password = \"e\";" fullword ascii
    $s15 = "vendorPropName = \"TEMP%\"," fullword ascii
    $s16 = "rcombinators[params](combinator.offset(), ((relative ^ 9), (funescape + 62), (evt ^ 0)), ((cos & 0) | (cos + -1)));" fullword ascii
    $s17 = "Expr[defer + extra][accepts]((2 * sortDetached + 1) * (cos * 2) * (xhrSupported + 0) * (cos * 2));" fullword ascii
    $s18 = "offsetWidth[winnow](rdisplayswap[responseText + readyWait + currentValue]);" fullword ascii
    $s19 = " vendorPropName + simulate) + tabIndex + letterSpacing + clearInterval + uniqueSort + readyWait + addClass + radioValue;" fullword ascii
    $s20 = "currentValue = \"eBody\", thead = \"Slee\", clone = 67, fast = \"ct\", _load = \"jec\";" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    1 of ($x*) and 4 of them
}