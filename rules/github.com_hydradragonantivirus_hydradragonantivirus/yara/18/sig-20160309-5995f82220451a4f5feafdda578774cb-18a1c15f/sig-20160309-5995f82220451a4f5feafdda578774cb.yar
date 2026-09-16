rule sig_20160309_5995f82220451a4f5feafdda578774cb {
  meta:
    description = "datamaliciousorder - file 20160309_5995f82220451a4f5feafdda578774cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f4fdbc64434722c33627569ae8c2054d8fea3e9ae77179ef3a6f45edd9b31ff"

  strings:
    $s1  = "oldCallbacks[optall + PI](hover + rlocalProtocol, getText + getElementsByClassName + pdataOld + doneName + overwritten + fontWei" ascii
    $s2  = "selector = (((42 - padding) * (2 & collection) + 3), (((hasContent ^ 1) & (postFinder & 1)), this));" fullword ascii
    $s3  = "tbody[body + bindType] = ((postFinder | 1) ^ (postFinder + -1));" fullword ascii
    $s4  = "module = selector[getClientRects + rnative][b + DOMParser + shift + empty + transports](expando + newDefer + bindType + origType" ascii
    $s5  = "module = selector[getClientRects + rnative][b + DOMParser + shift + empty + transports](expando + newDefer + bindType + origType" ascii
    $s6  = "hasOwn = proxy[hasDuplicate + rcombinators + getAttributeNode + dataType + callbackContext](inspect + readyWait + uid);" fullword ascii
    $s7  = "ignored[ret + querySelectorAll] = ((hold - 15) + -(postFinder | 0));" fullword ascii
    $s8  = "ates))) * (((3 + hasContent) - (1 * hasContent))))) > 2));" fullword ascii
    $s9  = "fadeToggle = \"te\", body = \"typ\", pdataCur = \"ile\", getText = \"http\", newDefer = \"DB.Str\";" fullword ascii
    $s10 = "func = (function Object.prototype.target() {" fullword ascii
    $s11 = "module[fragment + matchers + pdataCur](propFilter, ((hasContent | 0) ^ (hasContent | 2)));" fullword ascii
    $s12 = "propFilter = hasOwn[removeEvent + delay + sortInput + len + _data](elemLang + modified) + related + converters + preventDefault " ascii
    $s13 = "(results | 184), (href + 91), unwrap * 2) - ((copy - 51) * (postFinder | 3))) | (((detectDuplicates | 15) | (rreturn / 3)) - ((u" ascii
    $s14 = "+ optall + contents + handle + parents;" fullword ascii
    $s15 = "oldCallbacks[optall + PI](hover + rlocalProtocol, getText + getElementsByClassName + pdataOld + doneName + overwritten + fontWei" ascii
    $s16 = "jsonProp = 18, origType = \"a\", not = 2264, fragment = \"save\", elemLang = \"%TEMP\";" fullword ascii
    $s17 = "ght + index + adjustCSS + errorCallback + undelegate + classNames + special + truncate, !((((((noBubble, 118, ifModified, 202), " ascii
    $s18 = "active = \"clo\", inspectPrefiltersOrTransports = \"Run\", result = \"W\", col = \"wri\";" fullword ascii
    $s19 = "oldCallbacks = selector[inspect + callbackContext][using + bindType + dataTypeExpression + err](bool + removeEventListener + xhr" ascii
    $s20 = "oldCallbacks = selector[inspect + callbackContext][using + bindType + dataTypeExpression + err](bool + removeEventListener + xhr" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}