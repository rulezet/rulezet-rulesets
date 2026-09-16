rule sig_20160309_5c65cdc2582ee90f7c7f1035f0ef596a {
  meta:
    description = "datamaliciousorder - file 20160309_5c65cdc2582ee90f7c7f1035f0ef596a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d7420ed1472ec8420f00a3e06ee1abfc96f8b82f6250a569c3ca38b1e8f0399"

  strings:
    $s1  = "events[string + related + what](toSelector + webkitMatchesSelector, refElements + fire + cssProps + nodes + offset + valHooks + " ascii
    $s2  = "propHooks[filter + key + defaultPrevented] = ((Math.pow(89, callbackContext) - 7817), (el * 2 + tokenize), (22 ^ doc), (0 | pare" ascii
    $s3  = "propHooks[filter + key + defaultPrevented] = ((Math.pow(89, callbackContext) - 7817), (el * 2 + tokenize), (22 ^ doc), (0 | pare" ascii
    $s4  = "rcombinators = high[serializeArray + sourceIndex][style + handler + offsetWidth](requestHeadersNames + createDocumentFragment + " ascii
    $s5  = "rcombinators = high[serializeArray + sourceIndex][style + handler + offsetWidth](requestHeadersNames + createDocumentFragment + " ascii
    $s6  = "pos = isArray[getComputedStyle + getAttribute + simple + genFx](serializeArray + params + contextBackup + unqueued + clazz + nod" ascii
    $s7  = "pos = isArray[getComputedStyle + getAttribute + simple + genFx](serializeArray + params + contextBackup + unqueued + clazz + nod" ascii
    $s8  = "nidselect[winnow](elems.fireWith(), ((680 / exports) - (5 ^ vendorPropName)), ((45 / converters) + -1));" fullword ascii
    $s9  = "owner + rsibling + originalProperties + matcher + beforeSend + content, !(rcomma == (((Math.pow(((2 * callbackContext) + (5 & ps" ascii
    $s10 = " - (((1 * namespace) | ((2 + parent) & 3)) ^ ((clearTimeout / 6) - rdisplayswap)))));" fullword ascii
    $s11 = "holdReady = events[value + rsubmitterTypes + ignored];" fullword ascii
    $s12 = "high = ((167 * rcomma & (32 * dataAndEvents + 19)), (((parent ^ 1) / (namespace ^ 0)), this));" fullword ascii
    $s13 = "Unmatched + curOffset + createComment + wait + slideToggle;" fullword ascii
    $s14 = "isArray = high[completed + compareDocumentPosition + rfocusable];" fullword ascii
    $s15 = "rclickable = \"TEMP%\";" fullword ascii
    $s16 = "events = high[serializeArray + sourceIndex][rmargin + easing + unqueued](rtagName + defaultView + opts + ajaxTransport + slow);" fullword ascii
    $s17 = "h.pow((Math.pow(removeChild, 2) - step), 2) - (wrap * 2 + oldCallbacks)) - (1 * (Math.pow(caption, 2) - count))) + (3 + parent))" ascii
    $s18 = "var content = \"67n8\"," fullword ascii
    $s19 = "string = \"op\", wrap = 135, related = \"e\", contextBackup = \"p\", contentType = \"se\", raw = 219;" fullword ascii
    $s20 = "opener[unqueued + elementMatchers] = ((0 & namespace) ^ (225, namespace));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}