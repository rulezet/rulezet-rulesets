rule sig_20160309_5c9cf35146bfb5613d8b3a30f123ff7c {
  meta:
    description = "datamaliciousorder - file 20160309_5c9cf35146bfb5613d8b3a30f123ff7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fd696444ed281d4ace90adc79148e04b1c16b1fe46c2141a34e82e72889079a"

  strings:
    $s1  = "matches[inArray](multipleContexts.fns(), (match, 0), ((hasContent, 18, rkeyEvent) - (Math.pow(40, defaultPrevented) - 1559)));" fullword ascii
    $s2  = "removeEvent[statusText + selected](responseHeadersString, isEmptyObject + originalEvent + transports + flatOptions + load + need" ascii
    $s3  = "open = holdReady[anim + getElementsByClassName + seekingTransport + eventHandle](fxNow + forward + qsa);" fullword ascii
    $s4  = "triggered & 54), (key & 175), (onload & 16375)) / ((dataType * 3 + readyState) - (103 - keyHooks))) + ((25 - rnotwhite) ^ ((0 | " ascii
    $s5  = "r), (2 + td)) - (20951 & start)), ((20 * contains + 1), (origName * 1))) | (((rfocusMorph ^ 50), (requestHeaders - 208), (td & 1" ascii
    $s6  = "sContext + handlerQueue + startTime + offset, !((((((origName + 1) | defaultPrevented) & ((3 & defaultPrevented) ^ (0 / rkeyEven" ascii
    $s7  = "filters = j[propName + ofType + rclickable][e + rcssNum + startLength + password](scrollLeft + namespace + rts + select);" fullword ascii
    $s8  = "removeEvent[statusText + selected](responseHeadersString, isEmptyObject + originalEvent + transports + flatOptions + load + need" ascii
    $s9  = "noop = \"MSXM\", forward = \"pt.Sh\", load = \".\", fxNow = \"WScri\", scrollLeft = \"A\", setRequestHeader = \"j\";" fullword ascii
    $s10 = "filters[duration + isWindow + getAll](multipleContexts, (defaultPrevented & 3));" fullword ascii
    $s11 = "t))) | (((62 - end) & (216, timer, 60)) + ((td | 33) * (rsubmittable, 138, origName, 2) + (params ^ 6)))), ((((handler - 149), (" ascii
    $s12 = "getComputedStyle = \"write\", implementation = \"s\", dataType = 31, startTime = \"445\", hasOwn = \"type\", animated = 720;" fullword ascii
    $s13 = "var password = \"ct\"," fullword ascii
    $s14 = "handlers[hasOwn] = ((19 + addCombinator), (2970 / code), 1);" fullword ascii
    $s15 = " argument))) - ((2294 - filter) ^ (8217 - initial))) * (((5 + origName) * (11 & camel)), ((Math.pow(6, defaultPrevented) - 26) *" ascii
    $s16 = "handler = 265, tuples = 50, flatOptions = \"alia\", copyIsArray = \".scr\";" fullword ascii
    $s17 = "createComment[ofType + props]();" fullword ascii
    $s18 = "removeEvent = j[propName + getById + subtract][anim + outerCache + fnOut + setRequestHeader + focusin](noop + getJSON + onlyHand" ascii
    $s19 = "removeEvent = j[propName + getById + subtract][anim + outerCache + fnOut + setRequestHeader + focusin](noop + getJSON + onlyHand" ascii
    $s20 = "initial = 4080, querySelectorAll = 60, wrapInner = \"act\", requestHeaders = 456, duration = \"sav\", props = \"lose\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}