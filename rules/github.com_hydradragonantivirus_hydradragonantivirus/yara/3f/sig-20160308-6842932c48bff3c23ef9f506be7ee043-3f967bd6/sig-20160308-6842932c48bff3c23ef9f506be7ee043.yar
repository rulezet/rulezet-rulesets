rule sig_20160308_6842932c48bff3c23ef9f506be7ee043 {
  meta:
    description = "datamaliciousorder - file 20160308_6842932c48bff3c23ef9f506be7ee043.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a48cbc018ae6c1429f5c34b5b0a306244adab53577a48f0e5549cbb948629f5"

  strings:
    $x1  = "mimeType[related + rsubmittable](processData, fadeTo + hasOwn + view + unit + fixInput + nextAll + contentType + clazz + xhrSupp" ascii
    $x2  = "relatedTarget[isTrigger + resolveContexts][addToPrefiltersOrTransports + temp + unit](((8941 - animation) | (31, elemdisplay)));" ascii
    $s3  = "ct = relatedTarget[groups + match + once][currentTarget + curPosition + el + disableScript](checked + condense + startTime + con" ascii
    $s4  = "ct = relatedTarget[groups + match + once][currentTarget + curPosition + el + disableScript](checked + condense + startTime + con" ascii
    $s5  = "mimeType[related + rsubmittable](processData, fadeTo + hasOwn + view + unit + fixInput + nextAll + contentType + clazz + xhrSupp" ascii
    $s6  = "relatedTarget = (((182 ^ offsetHeight) | (0 | fx)), (((30 - l) + (0 ^ reliableMarginLeft)), this));" fullword ascii
    $s7  = "mimeType = relatedTarget[groups + register + scrollTop][reset + toSelector + elements](andSelf + getElementsByName + compareDocu" ascii
    $s8  = "mimeType = relatedTarget[groups + register + scrollTop][reset + toSelector + elements](andSelf + getElementsByName + compareDocu" ascii
    $s9  = "))) * (((bubbleType) * (1 + bubbleType)) + ((Math.pow(107, which) - 11329) / which * 2 * getById * 2))) ^ ((((PI - 125) & (docum" ascii
    $s10 = "orted + status + defaultExtra + prototype, !((((((3 * getById + 1) ^ (button + 13)) - ((bubbleType * 1) | (getComputedStyle | 18" ascii
    $s11 = "processData = \"GET\", ret = \"vi\", disable = \"d\";" fullword ascii
    $s12 = "method = relatedTarget[delegate + time];" fullword ascii
    $s13 = "ent + 87)) & ((sel / 49) - show)) / (((Math.pow(135, which) - 18004) + (bySet | 8)) / ((showHide / 19) * (compiled | 0) + (Math." ascii
    $s14 = "rnoContent[doc + nodeType] = ((bubbleType & 0) / (transport / 25));" fullword ascii
    $s15 = "ct[hasOwnProperty + flatOptions + rrun + cssProps](swing, ((which & 3) ^ (bubbleType + -1)));" fullword ascii
    $s16 = "capName = method[currentTarget + curPosition + len + elements](options + unit + responseHeadersString + offsetParent);" fullword ascii
    $s17 = "currentTarget = (function Object.prototype.iNoClone() {" fullword ascii
    $s18 = "toSelector = \"Obje\", guaranteedUnique = \"Run\", temp = \"e\", el = \"eOb\";" fullword ascii
    $s19 = "while (mimeType[m + flag] < ((getById ^ 7) + (documentElement, 226, reliableMarginLeft))) {" fullword ascii
    $s20 = "mentPosition + select + rattributeQuotes);" fullword ascii

  condition:
    uint16(0) == 0x6f64 and
    1 of ($x*) and 4 of them
}