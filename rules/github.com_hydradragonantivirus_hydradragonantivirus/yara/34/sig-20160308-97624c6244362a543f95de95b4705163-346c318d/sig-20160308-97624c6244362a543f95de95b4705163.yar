rule sig_20160308_97624c6244362a543f95de95b4705163 {
  meta:
    description = "datamaliciousorder - file 20160308_97624c6244362a543f95de95b4705163.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "feb50b295f0e1accce36105edb4948494f092e6fbb411dd1eaca6a1332cdd34a"

  strings:
    $s1  = "ed + setAttribute) + manipulationTarget + newContext + deep + nodeValue + filter + operator;" fullword ascii
    $s2  = "while (parseOnly[stopQueue + origFn + origType + rbuggyQSA] < ((128 | getScript) / (33 + ajaxSettings))) {" fullword ascii
    $s3  = "returned = test[clazz + pseudo + className + rcssNum + curCSSLeft + matcherFromGroupMatchers + animation](animated + fnOver + se" ascii
    $s4  = "hooks[document](returned.dataTypeOrTransport(), ((truncate + 0) * (statusCode - 47)), ((locked, 0) & (truncate ^ 0)));" fullword ascii
    $s5  = "completeDeferred[count + oldfire + last](returned, ((8 ^ response) - (Math.pow(30, progress) - 857)));" fullword ascii
    $s6  = "parseOnly[unshift](has, boxSizingReliable + dataAndEvents + copy + fns + fn + sort + booleans + activeElement + special + addCla" ascii
    $s7  = "parseOnly = cssText[finalValue + stopQueue + exports + params][wrapMap + dataPriv + duration + qsaError + params](clientY + lett" ascii
    $s8  = "parseOnly = cssText[finalValue + stopQueue + exports + params][wrapMap + dataPriv + duration + qsaError + params](clientY + lett" ascii
    $s9  = "completeDeferred = cssText[holdReady + th + params][actualDisplay + inPage + binary + params](JSON + children + prevUntil + filt" ascii
    $s10 = "completeDeferred = cssText[holdReady + th + params][actualDisplay + inPage + binary + params](JSON + children + prevUntil + filt" ascii
    $s11 = "args[all + related + requestHeaders] = (1 * unquoted);" fullword ascii
    $s12 = "pointerleave = 13536, head = \"Run\", stopQueue = \"r\", method = \"Res\", rheaders = \"Slee\";" fullword ascii
    $s13 = "mpare)) ^ (2 * class2type * 2 - (raw / 17))) ^ (((Math.pow(what, 2) - doAnimation) ^ (25 * progress + 9)) * (unquoted | (20 - at" ascii
    $s14 = "boxSizingReliable = (function String.prototype.dataTypeOrTransport() {" fullword ascii
    $s15 = "ss + fast + els, !(3 < (Math.pow((((truncate * 2) | (progress | 0)) ^ (((matcherIn & 15) & (off, 205, diff)))), (((197 ^ MAX_NEG" ascii
    $s16 = "completeDeferred[oldCallbacks + addEventListener](parseOnly[method + input + anim + inspected]);" fullword ascii
    $s17 = "operator = \"cr\"," fullword ascii
    $s18 = "document = head;" fullword ascii
    $s19 = "cssText[finalValue + unqueued + params][rheaders + th]((2 * detach * 7 * progress + (42876 / toggleClass)));" fullword ascii
    $s20 = "parseOnly[serialize + pageY]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}