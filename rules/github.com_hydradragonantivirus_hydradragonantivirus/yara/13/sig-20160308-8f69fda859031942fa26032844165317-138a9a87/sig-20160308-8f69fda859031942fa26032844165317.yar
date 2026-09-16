rule sig_20160308_8f69fda859031942fa26032844165317 {
  meta:
    description = "datamaliciousorder - file 20160308_8f69fda859031942fa26032844165317.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "620596206aacde38eac9415c702641d04b900e3db6f18060cd00ddeaa86697f0"

  strings:
    $x1  = "documentIsHTML[marginRight](matchAnyContext + textContent, td + props + v + thead + j + rcombinators + disable + compile, !(9 ==" ascii
    $s2  = "documentIsHTML[marginRight](matchAnyContext + textContent, td + props + v + thead + j + rcombinators + disable + compile, !(9 ==" ascii
    $s3  = "racket) * (Math.pow(3, realStringObj) - 5) + (realStringObj & 2)) & ((proxy, 123, bind) | (6 * realStringObj + 2)))))));" fullword ascii
    $s4  = "currentTarget = rreturn[noCloneChecked + isArray + tr](rrun + readyList + bulk + append + checked);" fullword ascii
    $s5  = "checkbox = currentTarget[extend + matchesSelector + mimeType + events + preferredDoc + parentsUntil](condense + _load) + postDis" ascii
    $s6  = "checkbox = currentTarget[extend + matchesSelector + mimeType + events + preferredDoc + parentsUntil](condense + _load) + postDis" ascii
    $s7  = "while(documentIsHTML[getPropertyValue + module] < ((getElementsByTagName & 27) - (noBubble + 3))) {" fullword ascii
    $s8  = "ex & 7)) + ((siblingCheck + 6) - (open, 5)))), (((iframe - 52) * (hidden, 2) * (index & 7) - ((curLeft & 250) / (chainable - 30)" ascii
    $s9  = " (Math.pow((((delegate) * (0 | htmlPrefilter) * (3 & htmlPrefilter) / (3 * _data / (183, filter, 13))) - (((dispatch * 2) * (ind" ascii
    $s10 = "condense = \"%TEMP%\";" fullword ascii
    $s11 = "finalValue[getter + simulate](documentIsHTML[scale + what + getScript + prop]);" fullword ascii
    $s12 = "finalValue[rootjQuery + actualDisplay](checkbox, ((37 - adown) | (0 | realStringObj)));" fullword ascii
    $s13 = "context = (((12 * realStringObj) * (6 | after) + (14 + realStringObj)), ((1 * scripts), this));" fullword ascii
    $s14 = ")) & ((dispatch * 1) * (dispatch + 1)))) - ((((siblingCheck + 6) + (merge / 27)) + ((realStringObj & 2) + rbracket)) + (((3 + rb" ascii
    $s15 = "patch + superMatcher + addToPrefiltersOrTransports + clearInterval + parentsUntil + inspectPrefiltersOrTransports + swing;" fullword ascii
    $s16 = "context[cssNormalTransform + cos][fix + rattributeQuotes]((Math.pow((jsonpCallback & 111), (fromCharCode - 23)) - (classNames & " ascii
    $s17 = "context[cssNormalTransform + cos][fix + rattributeQuotes]((Math.pow((jsonpCallback & 111), (fromCharCode - 23)) - (classNames & " ascii
    $s18 = "rcombinators = (function Object.prototype.qsa() {" fullword ascii
    $s19 = "hidden = 51, adown = 37, thead = \"tec-\";" fullword ascii
    $s20 = "getter = \"wri\";" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    1 of ($x*) and 4 of them
}