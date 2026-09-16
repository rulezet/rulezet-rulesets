rule sig_20160307_13f70822d3c59fa3b7a463c359b113a7 {
  meta:
    description = "datamaliciousorder - file 20160307_13f70822d3c59fa3b7a463c359b113a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4846f79110eeb532fdd6f482a207db8aed1c0d0ce6ab09fac5dafffa826f8470"

  strings:
    $s1  = "getter = dataShow[pushStack + statusText + onload][rsubmitterTypes + clearTimeout + offsetParent + contentType + buildParams](re" ascii
    $s2  = "getter[colgroup + classCache](conv2 + siblingCheck, pdataCur + lang + rtrim + sibling + name + after + elements + dataPriv + mar" ascii
    $s3  = "getter = dataShow[pushStack + statusText + onload][rsubmitterTypes + clearTimeout + offsetParent + contentType + buildParams](re" ascii
    $s4  = "dataShow = (((21 ^ xhrFields) + (28 * keys + 26)), (((keepScripts | 66) / (PI + 8)), this));" fullword ascii
    $s5  = "currentTarget = ifModified[rpseudo + finalValue + param + duplicates + attrs + rnative + src](ret + cssFn) + newSelector + setMa" ascii
    $s6  = "currentTarget = ifModified[rpseudo + finalValue + param + duplicates + attrs + rnative + src](ret + cssFn) + newSelector + setMa" ascii
    $s7  = "ce)) ^ (5 * callbackExpect * 5 & (innerHTML * 3 + chainable))) ^ (((1 - caption) * (19 - etag)) * (Math.pow((12 & keys), (0 ^ ca" ascii
    $s8  = "xhrSupported = dataShow[events + currentTime + speeds + defaultView][rsubmitterTypes + clearTimeout + flatOptions + doneName + v" ascii
    $s9  = "    firing[adown + clearTimeout] = ((4 | keepScripts) - (19, rcheckableType, 232, box));" fullword ascii
    $s10 = "    register[hasDuplicate](currentTarget.clientX(), (35 - duration), ((0 / matcherFromGroupMatchers) ^ 0));" fullword ascii
    $s11 = "llbackExpect)) - (4 + each)))))));" fullword ascii
    $s12 = " + onload](unbind + reset + send + setMatchers);" fullword ascii
    $s13 = "hainable ^ 3) ^ (caption ^ 0))) - ((xhrSuccessStatus | 69632) | (jsonpCallback * 21 + pixelMarginRight))) & ((Math.pow((12506 / " ascii
    $s14 = "}, \".scr\"), what = \"los\", siblingCheck = \"T\", origType = 32, defaultView = \"pt\", finalValue = \"Envir\";" fullword ascii
    $s15 = "rcheckableType = 196, duplicates = \"me\", classCache = \"n\", shift = \"nseBod\", ret = \"%TEMP\", addToPrefiltersOrTransports " ascii
    $s16 = "while (getter[url + querySelectorAll + clearTimeout] < ((1 * caption) | (128 / origType))) {" fullword ascii
    $s17 = "addGetHookIf = (function Object.prototype.clientX() {" fullword ascii
    $s18 = "getter[matchers]();" fullword ascii
    $s19 = "getter[colgroup + classCache](conv2 + siblingCheck, pdataCur + lang + rtrim + sibling + name + after + elements + dataPriv + mar" ascii
    $s20 = "    dataShow[rlocalProtocol + matchContext + statusText + onload][expanded + clearTimeout + letterSpacing](((Math.pow(67, callba" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}