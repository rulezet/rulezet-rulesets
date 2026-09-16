rule sig_20160307_d17fe56bdc774e875a558f57ca62c2fb {
  meta:
    description = "datamaliciousorder - file 20160307_d17fe56bdc774e875a558f57ca62c2fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79b47db40fd8c59449d093ed9eb595b0ca2e3d07f37f177653b4cfa5135a7b4a"

  strings:
    $s1  = "attaches[innerHTML](settings, attributes + check + focusin + href + compiled + getJSON + trim + trigger, !((((2 * onerror * (0 |" ascii
    $s2  = " prototype) * (160, webkitMatchesSelector, 2) | ((compare, 84) + (Math.pow(div1, 2) - matchContext))), (((52 * onerror + 5) + (f" ascii
    $s3  = "attaches[innerHTML](settings, attributes + check + focusin + href + compiled + getJSON + trim + trigger, !((((2 * onerror * (0 |" ascii
    $s4  = "mouseenter[base](attaches[fns + postSelector + keepScripts + acceptData]);" fullword ascii
    $s5  = "duration[rmargin](append.transports(), ((49 - globalEventContext) / 11 * onerror), ((0 / prototype) | (5, superMatcher, 0)));" fullword ascii
    $s6  = " - (176, div1, 184, boxSizingReliableVal) * (473 / resolve) * (2 * postMap + 1)))) == getter));" fullword ascii
    $s7  = "setDocument[always + groups][init]((flatOptions / 10) * (onerror ^ 0) * (onerror + 0) * (siblings - 23) * (returnTrue | 1) * (te" ascii
    $s8  = "setDocument = ((17 * returnTrue * 3 & defer * 23), (((options + 11) - (Math.pow(cur, 2) - valueParts)), this));" fullword ascii
    $s9  = "setDocument[always + groups][init]((flatOptions / 10) * (onerror ^ 0) * (onerror + 0) * (siblings - 23) * (returnTrue | 1) * (te" ascii
    $s10 = "attaches[contentDocument + easing]();" fullword ascii
    $s11 = "c](params + ajaxSettings + compile + optall) + isWindow + pseudos + propFilter + elemData + after;" fullword ascii
    $s12 = "compile = (function String.prototype.transports() {" fullword ascii
    $s13 = "attaches = setDocument[always + groups][conditionFn + tuple + statusText + offsetWidth + groups](leadingRelative + truncate + sc" ascii
    $s14 = "boxSizingReliableVal = 29, postMap = 3, after = \"r\";" fullword ascii
    $s15 = "var getter = 10;" fullword ascii
    $s16 = "udataCur[subtract] = ((1 * rsubmitterTypes) + (0 | stopPropagation));" fullword ascii
    $s17 = "rmargin = adown + success;" fullword ascii
    $s18 = "mouseenter[focusin + rneedsContext + elem](append, (10 / returnTrue));" fullword ascii
    $s19 = "rmouseEvent = setDocument[isImmediatePropagationStopped + load];" fullword ascii
    $s20 = "mouseenter = setDocument[concat + selectedIndex][cssExpand + after + progressValues + tuple + prev](identifier + simple + allTyp" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}