rule sig_20160307_ed1d03869f4eb27c2dfafbde15bf2e69 {
  meta:
    description = "datamaliciousorder - file 20160307_ed1d03869f4eb27c2dfafbde15bf2e69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca09e45068c290d332edb6253629e52ccb8a1ee32fec03820cb73f1f7c7d89e5"

  strings:
    $x1  = "initial[oMatchesSelector](disableScript, xml + htmlPrefilter + merge + getScript + contentType + slideUp + msMatchesSelector + a" ascii
    $s2  = "initial[oMatchesSelector](disableScript, xml + htmlPrefilter + merge + getScript + contentType + slideUp + msMatchesSelector + a" ascii
    $s3  = "    readyState[byElement] = (3 * contentDocument * 2 * bp, (Math.pow(78, load) - 5935), (el & 223), param);" fullword ascii
    $s4  = "load + 3)))), ((((attr | 0) | load) + ((0 & attr) / (Math.pow(14, load) - 170))) * (((attr | 25), (_ * 18 + adjustCSS), 1) + (ev" ascii
    $s5  = "byElement = \"type\", _ = 8, configurable = \"/\", add = \"WSc\", each = \"%TEMP%\";" fullword ascii
    $s6  = "forward = originalEvent[add + setFilters];" fullword ascii
    $s7  = "initial = originalEvent[add + evt + curLeft][max + open + define](nodes + addGetHookIf + shift + unquoted + copyIsArray);" fullword ascii
    $s8  = "initial[getWindow + fadeIn]();" fullword ascii
    $s9  = "originalEvent = (((3 + load), (1938 / matcherOut)), ((21 - url), this));" fullword ascii
    $s10 = "    triggered[props + rbracket + restoreScript](prevObject, ((hasCompare - 21) / (removeClass & 31)));" fullword ascii
    $s11 = "elemLang = \"ope\", returnFalse = \"posit\", seekingTransport = 53, contentType = (function String.prototype.pattern() {" fullword ascii
    $s12 = "triggered = originalEvent[add + rwhitespace + htmlPrefilter][attachEvent + compile](radio + isArrayLike + clientLeft);" fullword ascii
    $s13 = "up + stopOnFalse + cssNormalTransform + filters + ajax, !(1 < (((((seekingTransport * 2 + createFxNow) + 11 * load * 2) & ((chec" ascii
    $s14 = "prevObject = duration[one + cssExpand + completed + not + startLength + setTimeout + argument](each + configurable) + parents + " ascii
    $s15 = "prevObject = duration[one + cssExpand + completed + not + startLength + setTimeout + argument](each + configurable) + parents + " ascii
    $s16 = "duration = forward[max + htmlPrefilter + replaceAll + createCache](write + removeEvent + startTime);" fullword ascii
    $s17 = "while (initial[refElements + method + ignored] < ((bp + 1) & (load * 3 + param))) {" fullword ascii
    $s18 = "kNonElements * 3 + random) & 3 * matcherOut * 5)) + (((matchContext, 238, rmultiDash) + (135 | animate)) / ((30 ^ JSON) / (22 * " ascii
    $s19 = "rreturn = cssProps + before;" fullword ascii
    $s20 = "    cos[rreturn](prevObject.pattern(), ((param | 0) + -(param + 0)), (attr | (0 / adjustCSS)));" fullword ascii

  condition:
    uint16(0) == 0x7277 and
    1 of ($x*) and 4 of them
}