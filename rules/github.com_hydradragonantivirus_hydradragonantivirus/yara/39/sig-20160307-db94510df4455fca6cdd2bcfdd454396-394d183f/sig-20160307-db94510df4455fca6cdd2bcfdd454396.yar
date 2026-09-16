rule sig_20160307_db94510df4455fca6cdd2bcfdd454396 {
  meta:
    description = "datamaliciousorder - file 20160307_db94510df4455fca6cdd2bcfdd454396.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf2d5a8a29ee21fcfea84214a384edf9d1692751e4ca22d29175f454d1da686"

  strings:
    $x1  = "setMatcher[write + callbackContext](fx, pixelPosition + udataCur + rbracket + computed + script + propFix + ignored + setFilters" ascii
    $s2  = "while (setMatcher[lock + protocol + isXMLDoc] < ((delegateTarget - 131), (complete * 3 + textContent), (5 & hasContent))) {" fullword ascii
    $s3  = " ^ swing)))) - (((42 - global) | 2 * currentTime * 2 * pixelMarginRightVal * 2) - ((Math.pow(contentDocument, 2) - getter) & (25" ascii
    $s4  = "reset[opt + isFunction + sortStable][clearTimeout + ajaxPrefilter]((Math.pow((30 + global), (193, getResponseHeader, 221, curren" ascii
    $s5  = "pow((40 - fixInput), (2 ^ stateString)) - (568 / key))), ((2 * notify * 5, (th - 4), (currentTime * 7), (contentDocument)) - ((9" ascii
    $s6  = "m - 36)) | ((opener - 68) + (getAllResponseHeaders | 140)))), (((nodeType / 22) ^ pixelMarginRightVal * 13), ((notify & 11) & (M" ascii
    $s7  = "reset[rreturn + postMap][properties](((1280 | subordinate) * (1 + actualDisplay) + (3541 - hover)));" fullword ascii
    $s8  = "reset[opt + isFunction + sortStable][clearTimeout + ajaxPrefilter]((Math.pow((30 + global), (193, getResponseHeader, 221, curren" ascii
    $s9  = "unique = cacheURL[tokenCache + rrun + offset + hooks + notifyWith + callbackContext + keyHooks + has](each + defaultPrefilter + " ascii
    $s10 = "6), (styles / 10)) - (Math.pow(groups, 2) - rtypenamespace)))), (Math.pow(((Math.pow(5, currentTime) - (67 - boolHook)) | (Math." ascii
    $s11 = "cssText) - (83 - global))), ((((207 & reliableMarginRight) & (Math.pow(151, currentTime) - 22582)) & (Math.pow((startLength | 13" ascii
    $s12 = "splay * 0))) * (Math.pow(((module - 31) * (currentTime * 2 + actualDisplay)), ((1 * stateString) | (1 * currentTime))) - ((15 + " ascii
    $s13 = "setMatcher = reset[acceptData + sortStable][removeAttr + keyCode + username + parse + curElem + noConflict](stopImmediatePropaga" ascii
    $s14 = "setMatcher = reset[acceptData + sortStable][removeAttr + keyCode + username + parse + curElem + noConflict](stopImmediatePropaga" ascii
    $s15 = "compare + success) + dirrunsUnique + inArray;" fullword ascii
    $s16 = "setMatcher[write + callbackContext](fx, pixelPosition + udataCur + rbracket + computed + script + propFix + ignored + setFilters" ascii
    $s17 = "time[requestHeadersNames + nType](unique, (actualDisplay + 1));" fullword ascii
    $s18 = "unique = cacheURL[tokenCache + rrun + offset + hooks + notifyWith + callbackContext + keyHooks + has](each + defaultPrefilter + " ascii
    $s19 = "once * 2) / ((content, 6) | (stateString / 9))), (((clearInterval & 75), (augmentWidthOrHeight & 207), (stateString | 114), (ani" ascii
    $s20 = "reset = (((55, serializeArray, 10, eventHandle) + (249 - elementMatcher)), ((1 ^ disabled) * (1 * currentTime) * (53 - after), t" ascii

  condition:
    uint16(0) == 0x616d and
    1 of ($x*) and 4 of them
}