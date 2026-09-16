rule sig_20160309_f61e37b66115be35bfbb418e981ba6a9 {
  meta:
    description = "datamaliciousorder - file 20160309_f61e37b66115be35bfbb418e981ba6a9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca3202b8c2171c1006e1f246eee0724a0ee75d40c7d6e7625c0a5b0698c87345"

  strings:
    $x1  = "clientX[dispatch](stopped, isHidden + origFn + firstChild + fail + delegateTarget + fast + accepts + uniqueSort + oldfire + matc" ascii
    $s2  = "a) + then + jqXHR + cssNumber + compile + write + postDispatch + dirruns + forward + handlerQueue;" fullword ascii
    $s3  = "(((1 + relative) | (48 - attrHandle)) * (13 & (rneedsContext, 13)) * ((Math.pow(swap, 2) - token) - (23 & proxy)) ^ (((Math.pow(" ascii
    $s4  = "clientX[dispatch](stopped, isHidden + origFn + firstChild + fail + delegateTarget + fast + accepts + uniqueSort + oldfire + matc" ascii
    $s5  = " ((133, merge) ^ (1 * charset)))), (((39 + inspected)) / (Math.pow((32 | stopQueue), (1 * realStringObj)) - (13706 / host)))) - " ascii
    $s6  = "setPositiveNumber = jsonProp[createDocumentFragment + rrun + toArray + rCRLF + cloneCopyEvent + unshift](idx + reject + cleanDat" ascii
    $s7  = "5, realStringObj) - 16) * (relative * 2) + (relative | 1)) | ((rheaders / 18) / (merge * 7 + parse))))) > 1));" fullword ascii
    $s8  = "abort[sortStable + compile + curPosition + write] = ((1 + matchIndexes) + -1);" fullword ascii
    $s9  = "progressValues[attrId] = ((Math.pow(fire, 2) - href), (174 - wrapAll), (61 - charset), (26 / isImmediatePropagationStopped));" fullword ascii
    $s10 = "rCRLF = \"nment\", offsetHeight = \"ll\", delegateTarget = \"/s\", realStringObj = 2, ajaxExtend = \"tr\", forward = \"c\";" fullword ascii
    $s11 = "jsonProp = getAttribute[animate + hasScripts + getAll](mouseHooks + fcamelCase + sort + hookFn + unmatched + offsetHeight);" fullword ascii
    $s12 = "createComment[click + offsetWidth][username]((2 * realStringObj * 2 * realStringObj * 101 * realStringObj * 2 * realStringObj | " ascii
    $s13 = "rnumnonpx[scripts + write]();" fullword ascii
    $s14 = "createComment[click + offsetWidth][username]((2 * realStringObj * 2 * realStringObj * 101 * realStringObj * 2 * realStringObj | " ascii
    $s15 = "rnumnonpx[preferredDoc + oMatchesSelector + opacity](setPositiveNumber, ((suffix + 168), (MAX_NEGATIVE * 8 + wrapAll), (385 - it" ascii
    $s16 = "rnumnonpx[preferredDoc + oMatchesSelector + opacity](setPositiveNumber, ((suffix + 168), (MAX_NEGATIVE * 8 + wrapAll), (385 - it" ascii
    $s17 = "clientX = createComment[responseFields + getText + callback][rwhitespace + high + className + computed + callback](simple + cors" ascii
    $s18 = "clientX = createComment[responseFields + getText + callback][rwhitespace + high + className + computed + callback](simple + cors" ascii
    $s19 = "complete = clientX[children + setTimeout + msFullscreenElement + structure];" fullword ascii
    $s20 = "hers + pseudos + focus + xml, !((Math.pow((((realStringObj & 3) ^ (relative | (1 & relative))) ^ ((1 ^ (parse * 2 + relative)) ^" ascii

  condition:
    uint16(0) == 0x656e and
    1 of ($x*) and 4 of them
}