rule sig_20160308_35bcce6e156be7fcc4dae6cbb68efd58 {
  meta:
    description = "datamaliciousorder - file 20160308_35bcce6e156be7fcc4dae6cbb68efd58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "875ac345b46e8644cf62e11f261c8b77e51cf7f4b36b9028fb6fc5014d036457"

  strings:
    $x1  = "_$[nextSibling + rbuggyMatches](globalEventContext, index + url + split + nodeType + setFilters + swap + originalOptions + rrun " ascii
    $s2  = "m[off + head][b + fix](((ready + 528) & (Math.pow(transport, 2) - stopImmediatePropagation)));" fullword ascii
    $s3  = "OrTransport | 60)) & (keepScripts & (127 & high))), (((Math.pow(637, isPlainObject) - 405097) / (operator, 64, callback, 14)) - " ascii
    $s4  = "m[cssText + rheader + head][callbackName + defaultPrefilter + tokenize]((Math.pow((2508 / currentTarget), (20 - each)) - (Math.p" ascii
    $s5  = "m[cssText + rheader + head][callbackName + defaultPrefilter + tokenize]((Math.pow((2508 / currentTarget), (20 - each)) - (Math.p" ascii
    $s6  = "ainObject * 2 * cssNormalTransform * 3 - (Math.pow(hasContent, 2) - fired))), (((Math.pow(60, isPlainObject) - 3503) | (dataType" ascii
    $s7  = "_$ = m[off + head][rootjQuery + n + reset + head](completeDeferred + document + newSelector + matchers);" fullword ascii
    $s8  = "rquickExpr = m[cssText + delegateTarget][outermost + submit + add + overflowX + elementMatchers](throws + getBoundingClientRect " ascii
    $s9  = "rquickExpr = m[cssText + delegateTarget][outermost + submit + add + overflowX + elementMatchers](throws + getBoundingClientRect " ascii
    $s10 = "hasFocus = setTimeout[outermost + password + then + head](converters + callbackName + className + originalOptions + has + defaul" ascii
    $s11 = "hasFocus = setTimeout[outermost + password + then + head](converters + callbackName + className + originalOptions + has + defaul" ascii
    $s12 = "setRequestHeader = hasFocus[statusCode + isFunction + charCode + _jQuery](rcombinators + valueParts) + orig + preFilter + origin" ascii
    $s13 = "setRequestHeader = hasFocus[statusCode + isFunction + charCode + _jQuery](rcombinators + valueParts) + orig + preFilter + origin" ascii
    $s14 = "ansform)) ^ ((798 / filters) - (Math.pow(37, isPlainObject) - 1331))) | (((fire & 127) - (defineProperty - 87)) / ((fns / 14) / " ascii
    $s15 = ", (success & 175), (Math.pow(trigger, 2) - wrapMap), (1 + -tbody)) | ((8 * cssNormalTransform + 3) - cssNormalTransform * 3 * cs" ascii
    $s16 = "+ Sizzle + isEmptyObject + pop, !((Math.pow(((((168 - showHide) - (Math.pow(70, isPlainObject) - 4815)) ^ (Math.pow((setAttribut" ascii
    $s17 = "lpha)) - ((75 & firstElementChild) - (72 - filters)))) ^ ((((161 & success) | (Math.pow(1102, isPlainObject) - 1212832)) / (isPl" ascii
    $s18 = "while (_$[nodeNameSelector + cssHooks + overwritten] < (Math.pow((1 * cssNormalTransform), (0 | isPlainObject)) - (35 - setPosit" ascii
    $s19 = "while (_$[nodeNameSelector + cssHooks + overwritten] < (Math.pow((1 * cssNormalTransform), (0 | isPlainObject)) - (35 - setPosit" ascii
    $s20 = "doAnimation[winnow + propFilter] = ((Math.pow(110, isPlainObject) - 11888), (tbody + 0));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}