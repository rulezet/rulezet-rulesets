rule sig_20160309_02b31f9cd264af88f3c00126fa43baf2 {
  meta:
    description = "datamaliciousorder - file 20160309_02b31f9cd264af88f3c00126fa43baf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d949e3157552fb4c490f9986a3f9f3ffc661e0b869d260792f817e0d031df05"

  strings:
    $s1  = "rparentsprev[outerCache + toggleClass](check, root + disableScript + chainable + converters + addGetHookIf + firstChild + siblin" ascii
    $s2  = "getClientRects = guaranteedUnique[parseJSON + lastChild + throws + delegateTarget + removeAttr + noGlobal + rfocusable + off + m" ascii
    $s3  = "selector[slideToggle + rfocusable + radio] = ((217, find, 46, getBoundingClientRect), (39 * clone + 32), (bind - 45), (statusCod" ascii
    $s4  = "selector[slideToggle + rfocusable + radio] = ((217, find, 46, getBoundingClientRect), (39 * clone + 32), (bind - 45), (statusCod" ascii
    $s5  = "okenize) ^ (Math.pow(31, clone) - 901)))) ^ ((((size / 37) + (dirruns - 43)) / ((clone | 56) - (notify ^ 28))) * ((statusCode * " ascii
    $s6  = "- 50) * (valHooks / 41) + (reliableMarginLeft / 30))) ^ ((unwrap * 19 - (overrideMimeType * 6 + unwrap)) / ((184, notify, 234, t" ascii
    $s7  = "head[nodeIndex + memory + serializeArray + attachEvent](getClientRects, ((subtract - 8) ^ simulate));" fullword ascii
    $s8  = "propName[count](getClientRects.addBack(), ((0 | checkOn) & (1 * statusCode)), ((50, trim, 3, statusCode) * (0 / dirrunsUnique)))" ascii
    $s9  = "propName[count](getClientRects.addBack(), ((0 | checkOn) & (1 * statusCode)), ((50, trim, 3, statusCode) * (0 / dirrunsUnique)))" ascii
    $s10 = "settings = ((Math.pow((Math.pow(123, clone) - 14986), (clone & 3)) - (finalText - 14886)), (((jsonp + 28) / (timerId, 46)), this" ascii
    $s11 = "rparentsprev[outerCache + toggleClass](check, root + disableScript + chainable + converters + addGetHookIf + firstChild + siblin" ascii
    $s12 = "settings = ((Math.pow((Math.pow(123, clone) - 14986), (clone & 3)) - (finalText - 14886)), (((jsonp + 28) / (timerId, 46)), this" ascii
    $s13 = "guaranteedUnique = settings[scrollLeft + speed + returnTrue](dataAndEvents + getAttribute + stored + getWindow);" fullword ascii
    $s14 = "rparentsprev = settings[hidden + srcElements][has + protocol](valueIsBorderBox + isXML + addGetHookIf + allTypes + marginDiv);" fullword ascii
    $s15 = "head[propFilter + charCode]();" fullword ascii
    $s16 = "head = settings[p + serialize][has + condense + rfocusable](escapedWhitespace + err + token + parse);" fullword ascii
    $s17 = "atchers + nodeIndex](run + specialEasing) + event + removeAttr + rbrace + setter + activeElement;" fullword ascii
    $s18 = "check = \"GET\"," fullword ascii
    $s19 = "then = head;" fullword ascii
    $s20 = "head[childNodes](ajaxSetup);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}