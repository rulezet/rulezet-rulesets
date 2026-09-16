rule sig_20160308_74fd9b991e5080d9bad8ccf937841ccb {
  meta:
    description = "datamaliciousorder - file 20160308_74fd9b991e5080d9bad8ccf937841ccb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c11f1abc6bc8f5f26225ce76d614723d2d953e08fd31185ceceff27772310cf9"

  strings:
    $s1  = "rinputs[rfocusMorph + rtrim](delegateTarget + specialEasing, prevObject + document + onerror + replaceChild + option + rootjQuer" ascii
    $s2  = "relatedTarget[getJSON + rxhtmlTag + html + ajaxHandleResponses](dataAttr, (2 * charCode * 13, (contents, 134), (flatOptions ^ 27" ascii
    $s3  = "rinputs[rfocusMorph + rtrim](delegateTarget + specialEasing, prevObject + document + onerror + replaceChild + option + rootjQuer" ascii
    $s4  = "relatedTarget = bind[originAnchor + mozMatchesSelector][fnOver + getText + readyState](rdashAlpha + dirruns + rfocusable);" fullword ascii
    $s5  = "relatedTarget[getJSON + rxhtmlTag + html + ajaxHandleResponses](dataAttr, (2 * charCode * 13, (contents, 134), (flatOptions ^ 27" ascii
    $s6  = "dataTypes = getElementsByClassName[related + camelKey + nonce + rkeyEvent](swing + rcombinators + animated + cssNumber);" fullword ascii
    $s7  = "bind[getById + sibling + mozMatchesSelector][ajax + unquoted](((isWindow - 322) / (parentsUntil, 237, binary)));" fullword ascii
    $s8  = "rinputs = bind[rparentsprev + reliableMarginRight + rcombinators][computeStyleTests + pointerenter + ajaxHandleResponses + borde" ascii
    $s9  = "bind = (((Math.pow(31, charCode) - 922) & (bubbleType * 3 + fragment)), (((1 + globalEval) * (0 | globalEval)), this));" fullword ascii
    $s10 = "relatedTarget[nodeType + notifyWith](rinputs[selectedIndex + prop + status]);" fullword ascii
    $s11 = "r + preferredDoc + nonce + rkeyEvent](byElement + setFilters + slideDown);" fullword ascii
    $s12 = "bind[originAnchor + mozMatchesSelector][clone](((87347 / memory) * (30 - wrap) + 11 * computed * 2));" fullword ascii
    $s13 = "while (rinputs[send + timers + async] < ((38 * set + 30), (Math.pow(which, 2) - testContext), (Math.pow(3, charCode) - 5))) {" fullword ascii
    $s14 = "gment * 4)))) - (((charCode * 2) | (Math.pow(rescape, 2) - originalEvent)), ((79 ^ globalEval) & (95 & compare)), (644 / wrap) *" ascii
    $s15 = "border = \"a\", testContext = 41, stored = 7514, related = \"Creat\", preferredDoc = \"teOb\", delegateTarget = \"GE\";" fullword ascii
    $s16 = "one = \".scr\", onerror = \"//oz\", clone = \"Sleep\";" fullword ascii
    $s17 = " (0 ^ dataAndEvents) * (3 & dataAndEvents), ((11583 / getStyles) / (7 | slow)))))));" fullword ascii
    $s18 = "), (letter - 33)));" fullword ascii
    $s19 = "getElementsByClassName = bind[getById + getElementsByTagName];" fullword ascii
    $s20 = "rinputs = bind[rparentsprev + reliableMarginRight + rcombinators][computeStyleTests + pointerenter + ajaxHandleResponses + borde" ascii

  condition:
    uint16(0) == 0x7277 and
    8 of them
}