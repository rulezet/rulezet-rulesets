rule sig_20160307_9efed61ed6a3bee9359765efbe27ec47 {
  meta:
    description = "datamaliciousorder - file 20160307_9efed61ed6a3bee9359765efbe27ec47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26ab95315e24b3211d6ed50c4e9eff92b7cf8f1a36566bb740af5d9bdd4e430e"

  strings:
    $s1  = "outerCache[slow](list + fail, remaining + isSuccess + invert + getAll + rnoInnerhtml + filters + last + isNumeric + createElemen" ascii
    $s2  = "optSelected = 12, disableScript = \"sen\", createHTMLDocument = \"resp\", matchesSelector = \"%TEMP%\", doc = 132, settings = \"" ascii
    $s3  = "onreadystatechange = one[version + keepData][createTween + responseHeadersString + stop + tr](fxNow + isLocal + file);" fullword ascii
    $s4  = "onreadystatechange[pageXOffset + cloneNode + expand](tick, ((6 * rprotocol + 3) - (Math.pow(namespace, 2) - pageY)));" fullword ascii
    $s5  = "leteDeferred, 187, chainable) & (23 - exports))) - ((1032570 / hold) / 7 * raw * 2))) + ((((dataShow * 2) & raw) | ((Math.pow(37" ascii
    $s6  = "tick = bindType[returnFalse + until + stopPropagation + deep + stored + clientTop](matchesSelector + converters) + requestHeader" ascii
    $s7  = "tick = bindType[returnFalse + until + stopPropagation + deep + stored + clientTop](matchesSelector + converters) + requestHeader" ascii
    $s8  = ", chainable) - 1329) - (newSelector - 52))) + ((dataShow + -1) / (compare - 7))))));" fullword ascii
    $s9  = "one[settings + overflow + isSuccess][prop + cors + invert](((Math.pow(diff, 2) - rmultiDash)));" fullword ascii
    $s10 = "one[version + keepData][timers + invert](((args - 98) ^ (doc / 4)));" fullword ascii
    $s11 = "bindType = disable[src + whitespace + isSuccess](version + resolve + propFix + cors + nodes);" fullword ascii
    $s12 = "t + round + createHTMLDocument + duration + outermost + postFilter + fragment + addHandle + marginRight, !(rprotocol == (((((1 +" ascii
    $s13 = "outerCache[slow](list + fail, remaining + isSuccess + invert + getAll + rnoInnerhtml + filters + last + isNumeric + createElemen" ascii
    $s14 = "nativeStatusText[invert + prefix + relative + last] = (1 + -dataShow);" fullword ascii
    $s15 = "one = (((Math.pow(184, chainable) - 33620) & (xhrFields ^ 3)), (((max & 6) & (camel - 31)), this));" fullword ascii
    $s16 = "onreadystatechange[height + cors]();" fullword ascii
    $s17 = "disable = one[obj + completed + rwhitespace];" fullword ascii
    $s18 = "elemData = clearCloneStyle + Sizzle;" fullword ascii
    $s19 = "s + isSuccess + padding + valHooks;" fullword ascii
    $s20 = "outerCache = one[window + isSuccess][createComment + val + cors + parentNode + selection](originalSettings + submit + parseJSON " ascii

  condition:
    uint16(0) == 0x616d and
    8 of them
}