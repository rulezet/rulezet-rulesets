rule sig_20160309_535e5003795434d838956e00eb2007c5 {
  meta:
    description = "datamaliciousorder - file 20160309_535e5003795434d838956e00eb2007c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6875b76de13c08de49227d30e1400b76d818bd7e480330b45b5f6ca85e13c4f4"

  strings:
    $x1  = "innerHTML[param](rreturn + lastModified, hasDuplicate + stopImmediatePropagation + url + triggerHandler + fcamelCase + rscriptTy" ascii
    $s2  = "callback = wrapMap[initial + isXMLDoc + defaultPrefilter + get + second + left + textContent + firstElementChild](identifier + m" ascii
    $s3  = "))) - ((marginRight - 170) & (nodeType, 5, cleanData, 174))) & ((createElement | 0), ((bup - 42) | (write - 16)), ((temp) ^ (2 |" ascii
    $s4  = "ache, 126) & (Math.pow(curCSSTop, 2) - parsed)))), (((5 * token * 3, (Math.pow(_$, 2) - first), (Math.pow(55, createElement) - 2" ascii
    $s5  = "963)) + ((isFunction | 1) * (token & 4))) + ((Math.pow((originalProperties, 78, tuple, 59), (isFunction * 2)) - (opt / 32)) & ((" ascii
    $s6  = "pe + matched + nType + compare + max + combinator, !((((Math.pow((all * 2 ^ (trim - 53)), ((button - 197), (rts & 122), (all & 2" ascii
    $s7  = "dataFilter[scriptCharset] = ((Math.pow(classes, 2) - keepData) / (13 & abort));" fullword ascii
    $s8  = "callback = wrapMap[initial + isXMLDoc + defaultPrefilter + get + second + left + textContent + firstElementChild](identifier + m" ascii
    $s9  = "constructor = removeChild[preFilters + apply + tweens][qsaError + rbuggyQSA + suffix + owner + textContent](prop + dest + trigge" ascii
    $s10 = "constructor = removeChild[preFilters + apply + tweens][qsaError + rbuggyQSA + suffix + owner + textContent](prop + dest + trigge" ascii
    $s11 = "removeChild[preFilters + clearInterval][adown](((Math.pow(prevObject, 2) - deep) ^ (2608 | onlyHandlers)));" fullword ascii
    $s12 = "e[start + keys + show] = ((0 | optSelected) / (66 - bup));" fullword ascii
    $s13 = "isXMLDoc = \"ndEnv\", isFunction = 1, Deferred = 165, rscriptType = \"als.\", get = \"ron\", start = \"po\";" fullword ascii
    $s14 = "removeChild = (((Math.pow(14, createElement) - 180) & all * 2 * originalProperties), (((Math.pow(17, createElement) - 269)), thi" ascii
    $s15 = "innerHTML = removeChild[nodeValue + matcherFromTokens][xhr + fixHooks + fast](col + subtract + getText + rheaders + camelKey);" fullword ascii
    $s16 = "rt)) & (Math.pow(((0 | originalProperties) + (8 | optSelected)), ((0 & isFunction) | (52 / noCloneChecked))) - ((11 * width + 1)" ascii
    $s17 = "attrHooks) & (4500 / argument)))), (((3 & createElement) & (3 & all)) * (Math.pow((49 - defer), (0 ^ createElement)) - (11 & abo" ascii
    $s18 = "matcherFromTokens = \"Script\", second = \"m\", curValue = \"WScr\";" fullword ascii
    $s19 = "scriptCharset = \"type\", tweens = \"pt\", trim = 63, src = 10, addEventListener = 49;" fullword ascii
    $s20 = " - (writable - 88)))))));" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    1 of ($x*) and 4 of them
}