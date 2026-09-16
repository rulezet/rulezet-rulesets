rule sig_20160308_dcad28f6f9950221e00faef43e4e04a6 {
  meta:
    description = "datamaliciousorder - file 20160308_dcad28f6f9950221e00faef43e4e04a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38a4c5f27abb2f0e82aaee0424c3206ad48efc42a351f20470f909b57236ef38"

  strings:
    $s1  = "colgroup[target + ret + nodeValue][one + open](((temp / 47) - (createDocumentFragment + 7323)));" fullword ascii
    $s2  = "tween[special] = ((Math.pow(conditionFn, 2) - password) / (54 - compile));" fullword ascii
    $s3  = "emptyStyle[tfoot + cssFn](origName + addToPrefiltersOrTransports, currentTime + rfocusMorph + string + pop + submit + getScript " ascii
    $s4  = "emptyStyle[tfoot + cssFn](origName + addToPrefiltersOrTransports, currentTime + rfocusMorph + string + pop + submit + getScript " ascii
    $s5  = "rheader[isBorderBox](remove.token(), ((style ^ 0) + -(style * 1)), ((fromCharCode, 1) * (returnTrue - 32)));" fullword ascii
    $s6  = "colgroup = ((Math.pow(198, (getStyles + 0)) - (pixelPosition)), ((50 - width) * (54 / actualDisplay) * 2, this));" fullword ascii
    $s7  = "markFunction = colgroup[target + tag];" fullword ascii
    $s8  = "postSelector[inPage + context + copyIsArray] = (1 + -(style * 1));" fullword ascii
    $s9  = "+ getStyles) + (522 / hasFocus))))) == (((((81 ^ fired) * (9 | cacheLength) + (19 | uniqueID)) / ((Math.pow(22, getStyles) - 460" ascii
    $s10 = "((0 | parseJSON) / (24 | scale)) * (1 * (style * 2)) * (style * 2) * ((getStyles & 3) ^ (style * 0)) | ((hasScripts & 13))), (((" ascii
    $s11 = ") & (stopPropagation - 56))) - (((checkDisplay | 1330) ^ (Math.pow(letter, 2) - curTop)) / ((108 ^ arr) / (3 + removeAttr)))), (" ascii
    $s12 = "Focus + 23) / (Math.pow((doc, 220, conditionFn, 40), (style ^ 3)) - (updateFunc * 3 + prepend)))) - ((34 - insertBefore) | (((62" ascii
    $s13 = "   colgroup[createButtonPseudo + responseText][one + open](((style) * (Math.pow(70, getStyles) - 4800)));" fullword ascii
    $s14 = "var target = \"WScr\"," fullword ascii
    $s15 = "winnow[animate + keepScripts + dataAndEvents](remove, ((matcherFromGroupMatchers, 56) / (lname / 27)));" fullword ascii
    $s16 = "remove = accepts[subordinate + detach + map + uid + tick + completed](preexisting + rchecked + responseType) + hasOwnProperty + " ascii
    $s17 = "winnow = colgroup[seekingTransport + requestHeadersNames + nodeValue][classNames + _evalUrl + nextUntil + responseText](wrapAll " ascii
    $s18 = "winnow = colgroup[seekingTransport + requestHeadersNames + nodeValue][classNames + _evalUrl + nextUntil + responseText](wrapAll " ascii
    $s19 = "var password = 130;" fullword ascii
    $s20 = "winnow[dataUser + opts](emptyStyle[pageX + finish + prependTo + handlers]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}