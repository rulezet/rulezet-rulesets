rule sig_20160309_1364a8b496773a9d4f045abb32e45c70 {
  meta:
    description = "datamaliciousorder - file 20160309_1364a8b496773a9d4f045abb32e45c70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23ab2bc2bc5149258acfd60a995ae405502da311d9dec5629668f5cd466c7917"

  strings:
    $s1  = "rdashAlpha[next + Expr](matcherFromGroupMatchers, string + progressContexts + mozMatchesSelector + refElements + button + prev +" ascii
    $s2  = "nsform | 341) - (scrollTo + 146)) - ((tabIndex + 23) + (animate, 159, hasContent))), (((187 & slideDown), (60 + setRequestHeader" ascii
    $s3  = "dataShow[addToPrefiltersOrTransports + responseContainer + unloadHandler][parsed]((Math.pow((125, delegateCount, 96, scriptChars" ascii
    $s4  = "atched & 253), (rscriptType))) ^ ((7 * toggle - (1089 / scrollTo)) + (2 * toggle * (49 - trim) + 2))), (Math.pow((((cssNormalTra" ascii
    $s5  = "dataShow = ((Math.pow((3108 / parents), (157, keyHooks, 2)) - (propName & 30415)), ((unquoted), this));" fullword ascii
    $s6  = " getAllResponseHeaders + holdReady + finalText + animated, !(5 == ((((toArray & 7) ^ ((origName + 87), (documentIsHTML / 15), (m" ascii
    $s7  = "rdashAlpha = dataShow[valueIsBorderBox + stopPropagation][marginRight + addHandle + matchIndexes + blur](complete + preFilters +" ascii
    $s8  = "tyValue + size + getPropertyValue + find) + subordinate + returnFalse + querySelectorAll;" fullword ascii
    $s9  = "safeActiveElement = rprotocol[thead + diff + blur](valueIsBorderBox + bp + wrap);" fullword ascii
    $s10 = "step = safeActiveElement[position + createInputPseudo + _queueHooks + jsonp + getClientRects + constructor + fixInput](getProper" ascii
    $s11 = "step = safeActiveElement[position + createInputPseudo + _queueHooks + jsonp + getClientRects + constructor + fixInput](getProper" ascii
    $s12 = "view = 121644767, getAllResponseHeaders = \"ogs/76\", fail = \"XM\";" fullword ascii
    $s13 = "et), 2) - (view - 34330742)));" fullword ascii
    $s14 = "elemLang[sibling + rfocusMorph + fnOver] = (unquoted + -(0 ^ unquoted));" fullword ascii
    $s15 = "body[cssPrefixes + onreadystatechange + done]();" fullword ascii
    $s16 = " fail + protocol + _default + cssProps);" fullword ascii
    $s17 = "rdashAlpha = dataShow[valueIsBorderBox + stopPropagation][marginRight + addHandle + matchIndexes + blur](complete + preFilters +" ascii
    $s18 = "prev = \"/l\", css = \"e\", slideUp = \"writ\", querySelectorAll = \"r\", size = \"TEMP\";" fullword ascii
    $s19 = "body = dataShow[useCache + querySelectorAll + converters][serialize + matchIndexes + blur](assert + uniqueCache + booleans + get" ascii
    $s20 = "body = dataShow[useCache + querySelectorAll + converters][serialize + matchIndexes + blur](assert + uniqueCache + booleans + get" ascii

  condition:
    uint16(0) == 0x7277 and
    8 of them
}