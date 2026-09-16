rule sig_20160308_e696141cec7d85a896efe1c1ced1bcae {
  meta:
    description = "datamaliciousorder - file 20160308_e696141cec7d85a896efe1c1ced1bcae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e4ed74baa6e21d4cbc0460d798da18ffb3bda6fae2a30c1896fdc466c1ea12d"

  strings:
    $s1  = "timeoutTimer[sibling](parsed, uniqueID + activeElement + toggleClass + rxhtmlTag + createTextNode + delegate + key + removeEvent" ascii
    $s2  = "ridentifier[traditional](tweeners.rcheckableType(), original, ((1 + -contentType) ^ 0));" fullword ascii
    $s3  = "tweeners = cssText[restoreScript + bubbleType + _load + getElementsByClassName + isArray + replaceWith](overflowY + matches) + o" ascii
    $s4  = "while(timeoutTimer[startLength + isPlainObject + startTime + dirruns] < ((3 + contentType) & 3 * delegateCount)) {" fullword ascii
    $s5  = " + outermost + outerCache + maxIterations + fadeOut + specified + rhash, !((((Math.pow((overflowX + 133), (delegateCount & 2)) -" ascii
    $s6  = "(2 | original) + (33, contentType)), ((2574 / callbackInverse), (2280 / pointerenter), (43 | speeds), (1 * delegateCount))) - (5" ascii
    $s7  = "nid[rnoContent + sortDetached][appendTo]((1 * delegateCount) * (1 + contentType) * 5 * (factory + 0));" fullword ascii
    $s8  = "9 & excess)) / (((191, domManip, 1) * (contentType * 4)) + original)) * (((204, func, 1) + ((setFilters, 253, resolve, 0) ^ (con" ascii
    $s9  = "tentType * 0))) * ((contentType + (1 * delegateCount)) & (1 * (delegateCount + 1)))) > animation));" fullword ascii
    $s10 = "nid[fixHooks + view][appendTo](((optionSet - 372) ^ delegateCount * 3 * delegateCount * 2 * fadeTo));" fullword ascii
    $s11 = "rigFn + related + parentNode + token + uid + filters + startLength;" fullword ascii
    $s12 = "completeDeferred = nid[indirect + display][isXML + type + view](inspected + cleanData + handlerQueue + off);" fullword ascii
    $s13 = "completeDeferred[idx + Deferred + rmargin + animated](tweeners, (resolve / 36));" fullword ascii
    $s14 = "timeoutTimer = nid[dataTypes + initial][winnow + root + whitespace + setMatcher + acceptData](hasFocus + fnOver + flag + buildPa" ascii
    $s15 = "timeoutTimer = nid[dataTypes + initial][winnow + root + whitespace + setMatcher + acceptData](hasFocus + fnOver + flag + buildPa" ascii
    $s16 = " (nextAll ^ 15148394)) / ((pointerenter & 15) + (xml & 15))), ((original ^ 0) | delegateCount)) * ((Math.pow(((90 / contains) * " ascii
    $s17 = "rhash = \"4wg\", load = \"posi\", dirruns = \"state\", createInputPseudo = \"write\", startTime = \"y\", delegateCount = 2;" fullword ascii
    $s18 = "cssText = calculatePosition[realStringObj + identifier + rescape + animate](indirect + obj + Data + copy + inspectPrefiltersOrTr" ascii
    $s19 = "nid = ((2 * factory * 7 * delegateCount ^ (8 * delegateCount + 3)), (((delegateCount & 3) & (delegateCount & 2)), this));" fullword ascii
    $s20 = "childNodes[stopPropagation + animated] = 1;" fullword ascii

  condition:
    uint16(0) == 0x6975 and
    8 of them
}