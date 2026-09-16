rule sig_20160308_44d2fe239d173aee2c36ce7c485cebf0 {
  meta:
    description = "datamaliciousorder - file 20160308_44d2fe239d173aee2c36ce7c485cebf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b52deb6630d4b0f6c047a0c2cfe31d81127f15ba39450a5d9a2a4ae6bdcfdc9"

  strings:
    $s1  = "ready[modified + getText + seed](owner, ((1 - accepts) * (45 - clazz)));" fullword ascii
    $s2  = "target = \"DB.Str\";" fullword ascii
    $s3  = "qsaError = preexisting[parentWindow + t][conv2 + completeDeferred + xhrSupported](preFilter + fix + binary + factory + onlyHandl" ascii
    $s4  = "stopped[funcName](owner.clearInterval(), ((0 ^ isArray) + -(1 & isArray)), ((0 / timers) | (0 / headers)));" fullword ascii
    $s5  = "identifier = isPlainObject[divStyle + test + progressContexts](parentWindow + t + checkbox + restoreScript);" fullword ascii
    $s6  = "qsaError = preexisting[parentWindow + t][conv2 + completeDeferred + xhrSupported](preFilter + fix + binary + factory + onlyHandl" ascii
    $s7  = "ready = preexisting[parentWindow + t][rtypenamespace + active + interval + t](rescape + target + handlers);" fullword ascii
    $s8  = "qsaError[transport](window, abort + push + nextAll + rfocusable + split + cache + rmultiDash + structure + matchesSelector + isX" ascii
    $s9  = "owner = identifier[string + dest + event + ap + selectedIndex + num + dequeue + inArray](checkNonElements + fail + innerHTML) + " ascii
    $s10 = "owner = identifier[string + dest + event + ap + selectedIndex + num + dequeue + inArray](checkNonElements + fail + innerHTML) + " ascii
    $s11 = "ready[tokenCache + t + split](qsaError[timeoutTimer + acceptData + parentNode]);" fullword ascii
    $s12 = "MLDoc, !((((65, isBorderBox, 188, isArray) + ((7 + list) - (7 + isArray))) & ((((19, pointerleave, 3) / (isArray * 1)) | ((isArr" ascii
    $s13 = "preexisting[Symbol + getComputedStyle][unqueued + isWindow](((rCRLF | 2464) / (list * 13 + isArray)));" fullword ascii
    $s14 = "ready[props + replaceAll]();" fullword ascii
    $s15 = "matchIndexes + rhash + doc + method;" fullword ascii
    $s16 = "while (qsaError[rsubmittable + MAX_NEGATIVE + curCSSLeft + split] < ((raw / 28) / (onload / 6))) {" fullword ascii
    $s17 = "preexisting = ((Math.pow((77 + offsetParent), (4 / mouseenter)) - (28287 & wait)), (((29 & globalEventContext) - (112 / classes)" ascii
    $s18 = "preexisting = ((Math.pow((77 + offsetParent), (4 / mouseenter)) - (28287 & wait)), (((29 & globalEventContext) - (112 / classes)" ascii
    $s19 = "qsaError[transport](window, abort + push + nextAll + rfocusable + split + cache + rmultiDash + structure + matchesSelector + isX" ascii
    $s20 = "ready[transport]();" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}