rule sig_20160307_875dd33fbbe09fd4eaefacacd88a4e09 {
  meta:
    description = "datamaliciousorder - file 20160307_875dd33fbbe09fd4eaefacacd88a4e09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be7660e4f23582ea86546c62923af4a5daafbc95e9d7f2f96c62d8d83ce18f84"

  strings:
    $x1  = "parentWindow[preFilters + elements](p, oldCallbacks + temp + originalProperties + originalProperties + fix + htmlPrefilter + doc" ascii
    $s2  = "parentWindow = useCache[matchers + responseContainer + close][off + originalEvent + isPropagationStopped + args](outermost + con" ascii
    $s3  = "tent + processData + round + special);" fullword ascii
    $s4  = "temp = \"p:\";" fullword ascii
    $s5  = "umentElement + newUnmatched + tabIndex + root + bup + udataOld + serializeArray, !(((((Math.pow((462 / jsonp), (3 & dataAndEvent" ascii
    $s6  = "cssNormalTransform = cached[adjustCSS + scriptCharset + indirect + support](matchers + key + onreadystatechange + scripts + scri" ascii
    $s7  = "s)) - (324 ^ timerId)) - ((2 + scale) | (30 & host))) ^ (((30 / dataAttr) & (149, scale)) | ((1 * len) + -(3 / eventPath)))) * (" ascii
    $s8  = "cssNormalTransform = cached[adjustCSS + scriptCharset + indirect + support](matchers + key + onreadystatechange + scripts + scri" ascii
    $s9  = "(255 & elementMatchers)), ((33 / find) * (1 ^ eventPath))) - (101 * dataAndEvents * 5 * eventPath * (15 / eventPath) + (2382 | o" ascii
    $s10 = "parentWindow[preFilters + elements](p, oldCallbacks + temp + originalProperties + originalProperties + fix + htmlPrefilter + doc" ascii
    $s11 = "implementation[reliableMarginLeftVal](firing.progressValues(), ((len * 0) ^ scale), ((Math.pow(14, dataAndEvents) - 181), (nid &" ascii
    $s12 = "implementation[reliableMarginLeftVal](firing.progressValues(), ((len * 0) ^ scale), ((Math.pow(14, dataAndEvents) - 181), (nid &" ascii
    $s13 = "th.pow(grep, 2) - blur), (167 & offsetHeight), (Math.pow(94, dataAndEvents) - 8695), scale) ^ ((2 + scale) + (Math.pow(6, dataAn" ascii
    $s14 = "toSelector[attrNames + append](parentWindow[checkContext + tabIndex + attrHandle]);" fullword ascii
    $s15 = "last = \"%TEMP\";" fullword ascii
    $s16 = "clientX = 23, scriptCharset = (function Object.prototype.progressValues() {" fullword ascii
    $s17 = "firing = cssNormalTransform[rxhtmlTag + jQuery + results + truncate + prevAll + noCloneChecked + tabIndex](last + visibility) + " ascii
    $s18 = "firing = cssNormalTransform[rxhtmlTag + jQuery + results + truncate + prevAll + noCloneChecked + tabIndex](last + visibility) + " ascii
    $s19 = "host = 31," fullword ascii
    $s20 = "useCache[getText + nextAll][isTrigger](((2072 / toggle) + (44 & setMatcher)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}