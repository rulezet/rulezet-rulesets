rule sig_20160308_d4fcbaec449fe4c2fb969eafa205c0f1 {
  meta:
    description = "datamaliciousorder - file 20160308_d4fcbaec449fe4c2fb969eafa205c0f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "114b42b295df16167cbbad08bf2d6a8aa6b90c34eb9f094324a4715b46fec82d"

  strings:
    $s1  = "propFilter = fired[random + colgroup][offsetHeight + elements + lastChild + relatedTarget + unwrap](combinator + fix);" fullword ascii
    $s2  = "fired[qsaError + tr + fail + rcheckableType][delegateCount](((157, elemData, 139, throws), (Math.pow(164, initialInUnit) - 26707" ascii
    $s3  = "fired[qsaError + tr + fail + rcheckableType][delegateCount](((157, elemData, 139, throws), (Math.pow(164, initialInUnit) - 26707" ascii
    $s4  = "mapped = postSelector[readyState + camelKey + matcherOut + what + when](start + getAll + nodeIndex + visibility) + fail + focusi" ascii
    $s5  = "mapped = postSelector[readyState + camelKey + matcherOut + what + when](start + getAll + nodeIndex + visibility) + fail + focusi" ascii
    $s6  = "while (radio[memory + modified + bool] < ((Math.pow(overrideMimeType, 2) - left), (7 - cacheLength))) {" fullword ascii
    $s7  = "responses[shift + cssFn + fail + matchesSelector + nextAll] = ((opts | 0) ^ (factory + -1));" fullword ascii
    $s8  = "igger + condense + splice + promise, !((Math.pow((((Math.pow((pointerleave ^ 47), (initialInUnit & 2)) - (wrapInner + 509)) + (M" ascii
    $s9  = "trigger = \".com/o\";" fullword ascii
    $s10 = "fired = (((64 | parents) - 3), (((optSelected - 40) * (factory | 3)), this));" fullword ascii
    $s11 = "postSelector = multipleContexts[offsetHeight + memory + speed + handle](w + xhrSupported + now + callback + td + createInputPseu" ascii
    $s12 = "postSelector = multipleContexts[offsetHeight + memory + speed + handle](w + xhrSupported + now + callback + td + createInputPseu" ascii
    $s13 = "multipleContexts = fired[qsaError + rdashAlpha];" fullword ascii
    $s14 = "propFilter[border + bool](radio[Data + end + keys + pageY + response]);" fullword ascii
    $s15 = "radio[isSimulated + fadeOut](col + close, rnamespace + slow + always + jsonProp + pseudo + cssPrefixes + isHidden + curElem + tr" ascii
    $s16 = "getElementsByTagName = \"eTo\", splice = \"4g\";" fullword ascii
    $s17 = "num = \"a\", curElem = \"ejesus\", getAll = \"EM\", condense = \"097jhg\", initialInUnit = 2;" fullword ascii
    $s18 = "radio = fired[w + cssNormalTransform + rcheckableType][hasContent + num + events + e](startLength + caption + escapedWhitespace " ascii
    $s19 = "send = \"X\", lastChild = \"Ob\", createInputPseudo = \"Shell\", createHTMLDocument = 22;" fullword ascii
    $s20 = "propFilter[classNames + getElementsByTagName + linear + doneName](mapped, ((opts ^ 1) * (initialInUnit | 2)));" fullword ascii

  condition:
    uint16(0) == 0x6f68 and
    8 of them
}