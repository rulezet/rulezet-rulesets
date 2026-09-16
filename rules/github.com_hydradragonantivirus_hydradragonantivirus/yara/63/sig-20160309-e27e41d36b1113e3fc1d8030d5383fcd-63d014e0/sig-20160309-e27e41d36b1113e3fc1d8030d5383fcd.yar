rule sig_20160309_e27e41d36b1113e3fc1d8030d5383fcd {
  meta:
    description = "datamaliciousorder - file 20160309_e27e41d36b1113e3fc1d8030d5383fcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26cdf4838dcc9de9b5db860f21ae3d6f429f9257848dbb9eba2039cd48cc2235"

  strings:
    $x1  = "clientTop[pdataCur + timers](rmsPrefix, slow + speed + elementMatcher + sortDetached + rmouseEvent + matcherOut + deep + view + " ascii
    $s2  = "h.pow((70 - submit), (1 * prop)) - (32 | hookFn)), 31 * (base - 45), ((elemData + 58) & (delegateType ^ 29))) / (((getAttributeN" ascii
    $s3  = "tweeners = (((5 * thead + 3) & (firingIndex - 107)), ((start / 37), this));" fullword ascii
    $s4  = "adjusted = tweeners[curOffset + getAttribute + hasDuplicate + count][stored + events + root + compareDocumentPosition + addHandl" ascii
    $s5  = "adjusted = tweeners[curOffset + getAttribute + hasDuplicate + count][stored + events + root + compareDocumentPosition + addHandl" ascii
    $s6  = "unique[rscriptType + qsa]();" fullword ascii
    $s7  = "fireGlobals = clientTop[reliableMarginLeft + statusCode + notify + getBoundingClientRect];" fullword ascii
    $s8  = "focus[end](winnow.rnotwhite(), ((interval + -1) ^ (elements / 28)), (interval + -(0 | interval)));" fullword ascii
    $s9  = "clientTop = tweeners[curOffset + getStyles][serialize + checkContext + addHandle](hooks + ajaxTransport + insertBefore + rCRLF +" ascii
    $s10 = "strAbort[before + matchContext] = ((29 - optall) + -(9 - handleObj));" fullword ascii
    $s11 = "clientTop = tweeners[curOffset + getStyles][serialize + checkContext + addHandle](hooks + ajaxTransport + insertBefore + rCRLF +" ascii
    $s12 = "which + tokenCache + document + left + bubbleType + sourceIndex, !(prop < (((34 - delegateType) | (68 / delegateType))) * (((Mat" ascii
    $s13 = "ode - 37) + prop * 3) / ((elements | 1) | interval))) * ((((54 / errorCallback) / (0 | initial)) & (223, (interval & 1))) + (((e" ascii
    $s14 = "bySet = j[t + setDocument + transport + close + divStyle](capName + jsonProp + dataUser + r20);" fullword ascii
    $s15 = "    view = \"i.com/\"," fullword ascii
    $s16 = "clientTop[pdataCur + timers](rmsPrefix, slow + speed + elementMatcher + sortDetached + rmouseEvent + matcherOut + deep + view + " ascii
    $s17 = "adjusted[resolve + settings](fireGlobals);" fullword ascii
    $s18 = "adjusted[module + status + th](winnow, 2);" fullword ascii
    $s19 = "j = tweeners[self + fromCharCode];" fullword ascii
    $s20 = "tweeners[timerId + rquery + Data][ret + current](((pixelPositionVal & 1020) | (init & 16351)));" fullword ascii

  condition:
    uint16(0) == 0x6877 and
    1 of ($x*) and 4 of them
}