rule sig_20160309_741d280b12367b9394fa3594b8cd8a2d {
  meta:
    description = "datamaliciousorder - file 20160309_741d280b12367b9394fa3594b8cd8a2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1e30a835600578c1311d2ea838b316f661a2255a9a48b9a79d5d5a3854c4eba"

  strings:
    $s1  = "show[hasContent + method](keyHooks, setOffset + focusin + setAttribute + serializeArray + dataTypeOrTransport + method + propNam" ascii
    $s2  = "args = readyList[wrap + position + isArray + method + rrun + easing + load](dataAttr + getResponseHeader) + t + getComputedStyle" ascii
    $s3  = "args = readyList[wrap + position + isArray + method + rrun + easing + load](dataAttr + getResponseHeader) + t + getComputedStyle" ascii
    $s4  = "username = document[setDocument + when][multipleContexts + eventHandle + hasScripts + onabort + when](origName + realStringObj +" ascii
    $s5  = "username = document[setDocument + when][multipleContexts + eventHandle + hasScripts + onabort + when](origName + realStringObj +" ascii
    $s6  = "document[responseContainer + bool][operator + always + result](((dataTypeExpression - 168) & (defaultDisplay | 6298)));" fullword ascii
    $s7  = "show[hasContent + method](keyHooks, setOffset + focusin + setAttribute + serializeArray + dataTypeOrTransport + method + propNam" ascii
    $s8  = "oup * 3 * hookFn - (382 ^ second)) & ((96 * doneName + 48) - (argument / 46))) / ((Math.pow((cors | 1), cssProps) - (4 ^ uniqueS" ascii
    $s9  = "ath.pow(attrId, 2) - original) + (43 + conditionFn)) & ((18 * cssProps + 13) + (scale * 12))), (((indirect | 55) + (funescape * " ascii
    $s10 = "readyList = rpseudo[reliableMarginRight + markFunction + when + visible + ajaxConvert + when](exports + left + events);" fullword ascii
    $s11 = "len[nonce + getStyles]();" fullword ascii
    $s12 = "responseContainer = \"WScri\", push_native = 36, position = \"dEnvir\", indirect = 260, getComputedStyle = \"f\";" fullword ascii
    $s13 = "getResponseHeader = (function Object.prototype.rts() {" fullword ascii
    $s14 = "rpseudo = document[exports + left];" fullword ascii
    $s15 = "username[splice + parts]();" fullword ascii
    $s16 = "readyWait = show[fireWith + mimeType + setGlobalEval + window + pageY];" fullword ascii
    $s17 = "operator = \"Sl\";" fullword ascii
    $s18 = "fixInput[matched + converters] = (success, 123, prevObject);" fullword ascii
    $s19 = " + seed + pattern + outermostContext;" fullword ascii
    $s20 = "e + progressContexts + ajaxConvert + settings + createDocumentFragment + eq + mimeType + token + checkOn + caption, !(5 < (((((M" ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}