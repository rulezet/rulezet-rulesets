rule sig_20160308_dcc4c2d9cc9a5bcccb2def4ed4f73bad {
  meta:
    description = "datamaliciousorder - file 20160308_dcc4c2d9cc9a5bcccb2def4ed4f73bad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bdf4c24af8f3eab1ef46f517b01058e01390f51c6fa7b101d0b598eac2c1b3c"

  strings:
    $s1  = "rtypenamespace[setTimeout](keepScripts + lang, compiled + calculatePosition + insertBefore + match + msFullscreenElement + compl" ascii
    $s2  = "ignored[animated + contents][clearCloneStyle + map](((6 ^ propFix), (24 | offsetWidth), (Math.pow(139, compareDocumentPosition) " ascii
    $s3  = "preexisting = adjusted[setMatchers + setRequestHeader + iterator + matches + easing + addEventListener](clientX + host + assert " ascii
    $s4  = "preexisting = adjusted[setMatchers + setRequestHeader + iterator + matches + easing + addEventListener](clientX + host + assert " ascii
    $s5  = "ete + transport + tokens + stopQueue, !(9 == ((Math.pow((Math.pow((Math.pow((compareDocumentPosition * 2), (resolveContexts / 9)" ascii
    $s6  = "ignored[animated + contents][clearCloneStyle + map](((6 ^ propFix), (24 | offsetWidth), (Math.pow(139, compareDocumentPosition) " ascii
    $s7  = "end[original](preexisting.support(), ((32 - abort) + -(1 + contextBackup)), ((13 & copyIsArray), (33 * compareDocumentPosition +" ascii
    $s8  = "rtypenamespace = ignored[animated + contents][blur + invert + animate + second + contents](byElement + addBack + prependTo + rmo" ascii
    $s9  = "end[original](preexisting.support(), ((32 - abort) + -(1 + contextBackup)), ((13 & copyIsArray), (33 * compareDocumentPosition +" ascii
    $s10 = ") - (testContext & 14)), (compareDocumentPosition | (1 + -offsetWidth))) - ((44 ^ define) - (31 & send))), (((123 / compare) & (" ascii
    $s11 = "ignored = ((2 * implementation * 2 * specified / (46 & disableScript)), (((207, testContext) + (12 & testContext)), this));" fullword ascii
    $s12 = "ignored[animated + contents][Deferred + callbackContext](((parsed) - (183862 / elements)));" fullword ascii
    $s13 = "+ bulk) + finish + getWidthOrHeight + p + dataShow + match + createElement;" fullword ascii
    $s14 = "add = ignored[animated + contents];" fullword ascii
    $s15 = "adjusted = add[inspected + matcherIn + startTime](emptyGet + _evalUrl + attrNames + promise);" fullword ascii
    $s16 = "while (rtypenamespace[clearInterval + obj + contents + push_native] < ((4 & hasData) + (0 | contextBackup))) {" fullword ascii
    $s17 = "rtypenamespace[setTimeout](keepScripts + lang, compiled + calculatePosition + insertBefore + match + msFullscreenElement + compl" ascii
    $s18 = "rtypenamespace = ignored[animated + contents][blur + invert + animate + second + contents](byElement + addBack + prependTo + rmo" ascii
    $s19 = "9)) * ((fns - 19) - (globalEventContext * 17 + offsetWidth))) + (((24 ^ unquoted) + (2 ^ contextBackup)) - ((104 / ofType) | (28" ascii
    $s20 = "w[preFilter + settings] = (21 - define);" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}