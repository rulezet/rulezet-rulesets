rule sig_20160308_623baf15b5820f86f7981652bce912b3 {
  meta:
    description = "datamaliciousorder - file 20160308_623baf15b5820f86f7981652bce912b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7a438493c1dfa819d09f7921d5d30c6694880e5e3545a56a6076f4bce483da5"

  strings:
    $s1  = "rCRLF[nextSibling](computed, checkbox + indirect + rnoContent + handler + prefilterOrFactory + rfocusMorph + html + rbuggyMatche" ascii
    $s2  = "firstElementChild[submit + get](open, ((1 + -startLength) ^ (2 | defaultPrefilter)));" fullword ascii
    $s3  = "s, !(8 < (((((root, 0) / (curCSSTop / 43)) | ((firingIndex) / 2 * offsetWidth * 5)) + (((eventHandle ^ 156) - (unique ^ 1)) / ((" ascii
    $s4  = "firstElementChild[acceptData + preFilters + createPseudo](rCRLF[dataFilter + which + cssProps + target + createPositionalPseudo]" ascii
    $s5  = "target = \"od\";" fullword ascii
    $s6  = "firstElementChild[acceptData + preFilters + createPseudo](rCRLF[dataFilter + which + cssProps + target + createPositionalPseudo]" ascii
    $s7  = "while (rCRLF[callbackInverse + rscriptType + noConflict] < ((setAttribute & 4) ^ (tweens - 46))) {" fullword ascii
    $s8  = "tween = currentTarget;" fullword ascii
    $s9  = "getClass[tween](open.emptyStyle(), (1 * defaultPrefilter), ((8 | selectors), (1 + -startLength)));" fullword ascii
    $s10 = "rCRLF[nextSibling](computed, checkbox + indirect + rnoContent + handler + prefilterOrFactory + rfocusMorph + html + rbuggyMatche" ascii
    $s11 = "callbackExpect[outerCache + buildParams][onload]((Math.pow((createDocumentFragment / 24), (end)) - (5984 & copy)));" fullword ascii
    $s12 = "callbackExpect = (((13 | restoreScript)), (((10 | amd) + (1 + defaultPrefilter)), this));" fullword ascii
    $s13 = "firstElementChild[mouseHooks + relative]();" fullword ascii
    $s14 = "tive + then + container);" fullword ascii
    $s15 = "open = isXML[returned + argument + expanded + stopPropagation + optSelected + removeAttr + msFullscreenElement](chainable + inne" ascii
    $s16 = "open = isXML[returned + argument + expanded + stopPropagation + optSelected + removeAttr + msFullscreenElement](chainable + inne" ascii
    $s17 = "isXML = groups[allTypes + what + tag + rejectWith](keepData + left + bp);" fullword ascii
    $s18 = "rHTML + nType) + add + createPseudo + method + setGlobalEval + strAbort;" fullword ascii
    $s19 = "root = 76;" fullword ascii
    $s20 = "submit = \"save\";" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}