rule sig_20160309_3ba4a813582798f18fb2eff1df15ac31 {
  meta:
    description = "datamaliciousorder - file 20160309_3ba4a813582798f18fb2eff1df15ac31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b58866ea11e4e90052417cbf85673efae5727c724a3e1f36c1c926eaa54f81c"

  strings:
    $s1  = "params[addCombinator + responseText](append + setGlobalEval, setTimeout + offsetParent + removeEventListener + configurable + cu" ascii
    $s2  = "hash[i](isReady.rkeyEvent(), (1 * unloadHandler), (1 * (hasScripts * 0)));" fullword ascii
    $s3  = "rCSSTop + emptyStyle + _evalUrl + subordinate, !(n == ((((Math.pow((12 ^ groups), (0 ^ lname)) - (386 | requestHeadersNames)) + " ascii
    $s4  = "className[marginRight + origType + tokenCache][speed + send + addHandle]((Math.pow((2859 + jsonProp), (1 * lname)) - (70621185 &" ascii
    $s5  = "isReady = push_native[currentValue + tweens + rcombinators + proxy + pattern + each + src](setter + el) + parentNode + origType " ascii
    $s6  = "isReady = push_native[currentValue + tweens + rcombinators + proxy + pattern + each + src](setter + el) + parentNode + origType " ascii
    $s7  = "((352 | callbackExpect) / (37 - tick))), (Math.pow(((1 * hasScripts) | (Math.pow(18, lname) - 299)), ((modified, 2) & (parseJSON" ascii
    $s8  = "params = className[script + values][disable + toArray + _$ + responses + condense + animated + values](head + pixelMarginRightVa" ascii
    $s9  = "params = className[script + values][disable + toArray + _$ + responses + condense + animated + values](head + pixelMarginRightVa" ascii
    $s10 = "er), 2 * prevUntil, (1 + -hasScripts))) | (((0 / classes) | (16 / oldCache)) * (94 / keepScripts) + (0 | hasScripts)))));" fullword ascii
    $s11 = "className[marginRight + origType + tokenCache][speed + send + addHandle]((Math.pow((2859 + jsonProp), (1 * lname)) - (70621185 &" ascii
    $s12 = "params[addCombinator + responseText](append + setGlobalEval, setTimeout + offsetParent + removeEventListener + configurable + cu" ascii
    $s13 = "special = \"Body\", addCombinator = \"op\", prevUntil = 109, offsetParent = \"/\", script = \"WScrip\", rneedsContext = 31;" fullword ascii
    $s14 = "defaultValue = className[script + values][delegateCount + hasDuplicate + timeout](cloneCopyEvent + matchAnyContext + values + ri" ascii
    $s15 = "etag = className[keyCode + animated + rcheckableType + getAllResponseHeaders];" fullword ascii
    $s16 = "head = \"MSXM\", rcombinators = \"nviro\";" fullword ascii
    $s17 = "var src = (function Object.prototype.rkeyEvent() {" fullword ascii
    $s18 = "rIn, 2) - newContext)) * ((14 ^ rneedsContext) * (8 - xhrFields) + (131, merge, 13)), ((method / 40), (createTween * 3 + contain" ascii
    $s19 = "defaultValue[view + rclass + origType + send](isReady, (51 - has));" fullword ascii
    $s20 = "className = ((171 - unshift), (((1 * n) ^ (Math.pow(5, lname) - 17)), this));" fullword ascii

  condition:
    uint16(0) == 0x245f and
    8 of them
}