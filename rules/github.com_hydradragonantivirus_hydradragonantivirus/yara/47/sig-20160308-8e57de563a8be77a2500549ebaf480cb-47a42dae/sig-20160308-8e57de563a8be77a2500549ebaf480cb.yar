rule sig_20160308_8e57de563a8be77a2500549ebaf480cb {
  meta:
    description = "datamaliciousorder - file 20160308_8e57de563a8be77a2500549ebaf480cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b686b6da4d376272c5b13e4bf516201ec6260785382dfdea7e03ac6f1a963eb0"

  strings:
    $s1  = "rneedsContext[_jQuery + getComputedStyle](duration, curOffset + replaceChild + w + relative + textContent + url + Sizzle + PI + " ascii
    $s2  = "rneedsContext[_jQuery + getComputedStyle](duration, curOffset + replaceChild + w + relative + textContent + url + Sizzle + PI + " ascii
    $s3  = "keyHooks[clientLeft](i.bind(), ((fixHook * 0) ^ (fixHook + -1)), ((bulk / 15) | (fixHook * 0)));" fullword ascii
    $s4  = "rneedsContext = isArray[wrapMap + responses + ajax][resolveContexts + rmargin + collection + lname + ready](responseHeadersStrin" ascii
    $s5  = "rneedsContext = isArray[wrapMap + responses + ajax][resolveContexts + rmargin + collection + lname + ready](responseHeadersStrin" ascii
    $s6  = "special[_jQuery + getComputedStyle]();" fullword ascii
    $s7  = "find, !(fixHook == (((Math.pow(((3 + strAbort) ^ (92, responseText)), (1 ^ MAX_NEGATIVE)) - ((11703 / winnow) & 2 * eased * 59))" ascii
    $s8  = "isArray = (2 * (Math.pow(uniqueSort, 2) - siblingCheck), (((206, old) - (Math.pow(5, eased) - 17)), this));" fullword ascii
    $s9  = "getClass = 50, uniqueSort = 65, radioValue = \"L2.XM\", opts = \"Respon\", password = \"type\", invert = \"%/\";" fullword ascii
    $s10 = "isArray[locked + getAttributeNode][checkNonElements + then](((28 * matchedCount + 21), eased * 2 * matchedCount * 5));" fullword ascii
    $s11 = "get = isArray[locked + isHidden + jqXHR];" fullword ascii
    $s12 = "fns = get[resolveContexts + callbackName + ready](window + createElement + obj);" fullword ascii
    $s13 = "special[guaranteedUnique + settings + _$](i, ((stop - 27) + (tag - 21)));" fullword ascii
    $s14 = "special = isArray[window + callbackInverse + isHidden + jqXHR][getAttribute + send + run + camel](delay + setDocument + empty + " ascii
    $s15 = "clearCloneStyle[password] = ((winnow / 47));" fullword ascii
    $s16 = "special = isArray[window + callbackInverse + isHidden + jqXHR][getAttribute + send + run + camel](delay + setDocument + empty + " ascii
    $s17 = "isArray[createCache + camel][vendorPropName + handleObjIn + attachEvent]((Math.pow((scale | 9386), (fixHook * 2)) - (genFx / 27)" ascii
    $s18 = "isArray[createCache + camel][vendorPropName + handleObjIn + attachEvent]((Math.pow((scale | 9386), (fixHook * 2)) - (genFx / 27)" ascii
    $s19 = "while(rneedsContext[simple + prev + camel + rmargin + defaultDisplay] < ((1 | doc) - (4 + MAX_NEGATIVE))) {" fullword ascii
    $s20 = "isPropagationStopped[dataAttr + insertAfter + init] = ((bulk / 10) ^ (bulk | 0));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}