rule sig_20160309_267e55604946e35d185257fbf2a3a71e {
  meta:
    description = "datamaliciousorder - file 20160309_267e55604946e35d185257fbf2a3a71e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afe8303e344513e2cdaa8b9aaf59ff0c840d21c9cd55bf88d81e20affc30215d"

  strings:
    $s1  = "fragment[emptyGet](idx, valHooks + setter + pointerenter + password + easing + ajaxExtend + focus + nextAll + combinator + group" ascii
    $s2  = "fragment[emptyGet](idx, valHooks + setter + pointerenter + password + easing + ajaxExtend + focus + nextAll + combinator + group" ascii
    $s3  = "target = p[PI + mouseHooks + rscriptType + inspect + unwrap + getAttributeNode + responseHeadersString](genFx + origFn) + remain" ascii
    $s4  = "target = p[PI + mouseHooks + rscriptType + inspect + unwrap + getAttributeNode + responseHeadersString](genFx + origFn) + remain" ascii
    $s5  = "progress[msMatchesSelector](target.appendChild(), ((1 + -props) | (44 - rneedsContext)), ((49, matchExpr, 11, returnFalse) / 2))" ascii
    $s6  = "progress[msMatchesSelector](target.appendChild(), ((1 + -props) | (44 - rneedsContext)), ((49, matchExpr, 11, returnFalse) / 2))" ascii
    $s7  = "split = (((78, rpseudo, 22) ^ (Math.pow(document, 2) - newSelector)), (((1 + -props) | (1 ^ rrun)), this));" fullword ascii
    $s8  = "dataAttr[lastChild + originAnchor + unwrap](target, ((returnFalse / 39) ^ (props + 1)));" fullword ascii
    $s9  = "split[guid + documentIsHTML][reverse]((Math.pow((status * 15 + inspected), (52 - responseText)) - (110854076 ^ test)));" fullword ascii
    $s10 = "dataAttr = split[disableScript + matches + select + accepts][cssNumber + makeArray + accepts](matcherOut + submit + appendTo + i" ascii
    $s11 = "dataAttr = split[disableScript + matches + select + accepts][cssNumber + makeArray + accepts](matcherOut + submit + appendTo + i" ascii
    $s12 = "compare[scripts]();" fullword ascii
    $s13 = "| (1 + returnFalse)) ^ ((113, thead, 241, Sizzle) ^ (1 * props)))) == 7));" fullword ascii
    $s14 = "sortInput = split[getElementsByName + accepts];" fullword ascii
    $s15 = "currentValue = \"WScri\", password = \"nind.c\", newSelector = 28011, document = 168;" fullword ascii
    $s16 = "ing + ready + clientY + completed + unwrap + dataFilter + outerCache;" fullword ascii
    $s17 = "focus = \"ste\", mouseenter = \"Create\", rscriptType = \"viron\", pointerenter = \"hsa\";" fullword ascii
    $s18 = "p = sortInput[mouseenter + th + createDocumentFragment](currentValue + select + id + htmlPrefilter);" fullword ascii
    $s19 = "fragment = split[els + parentNode][_ + xml + rbuggyQSA + open](isImmediatePropagationStopped + conv2 + scrollLeft + letter + cor" ascii
    $s20 = "buildFragment[adjustCSS + extra] = (props * 1);" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}