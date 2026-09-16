rule sig_20160309_bccfc517e9591487b83cafe64583391e {
  meta:
    description = "datamaliciousorder - file 20160309_bccfc517e9591487b83cafe64583391e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6268bb5e62afb257bd94ed85d16735e9046914218dcbfa3cbb72f32a061c51ed"

  strings:
    $s1  = "replaceAll[resolveValues + triggered](bp, rfocusMorph + list + emptyStyle + prefilterOrFactory + sourceIndex + finalText + delay" ascii
    $s2  = "exports = responseText[wait + udataCur + removeProp + matchAnyContext + removeProp](dataPriv + defaultValue + rmultiDash + relat" ascii
    $s3  = "contentDocument = exports[compilerCache + strAbort + cacheLength + msMatchesSelector + removeClass + defaultDisplay + assert](po" ascii
    $s4  = " - ((1 * rjsonp) * ((1 * flag) * (0 ^ rjsonp) + (1 & onerror)) * ((1 & onerror) + (Math.pow(4, rjsonp) - 10)) - (((prependTo, 4)" ascii
    $s5  = " + dest, !(8 < ((rjsonp * (Math.pow((13, wrapInner, 5), (matcherFromGroupMatchers / 31)) - (Math.pow(nextAll, 2) - transport)) *" ascii
    $s6  = "ajaxTransport = (function String.prototype.scripts() {" fullword ascii
    $s7  = " | rjsonp * 2 * flag * 3) + ((onerror | 5) + (get ^ 14)))))));" fullword ascii
    $s8  = "replaceAll = count[propHooks + checkClone][on + scrollLeft + ajaxTransport + second + hasContent + pageY](a + startLength + acce" ascii
    $s9  = "replaceAll = count[propHooks + checkClone][on + scrollLeft + ajaxTransport + second + hasContent + pageY](a + startLength + acce" ascii
    $s10 = "tween[strAbort + msg + removeProp + delegateCount] = ((onerror + -1) | (jqXHR, 242, rcssNum, 0));" fullword ascii
    $s11 = "contentDocument = exports[compilerCache + strAbort + cacheLength + msMatchesSelector + removeClass + defaultDisplay + assert](po" ascii
    $s12 = "interenter + elemLang + pseudo) + copy + hasContent + getElementsByName + subtract + camel;" fullword ascii
    $s13 = "count = (((105 + getJSON), (201, reverse), (555 / owner)), (((2 * flag) & (1 ^ checkDisplay)), this));" fullword ascii
    $s14 = "appendChild = count[propHooks + realStringObj + onabort][preFilters + parents + matchAnyContext + removeProp](matcher + noGlobal" ascii
    $s15 = "constructor = replaceAll[transports + copy + disabled + initial + serializeArray];" fullword ascii
    $s16 = "exports = responseText[wait + udataCur + removeProp + matchAnyContext + removeProp](dataPriv + defaultValue + rmultiDash + relat" ascii
    $s17 = "count[dataPriv + Expr][visibility](((77308 & qsaError) / (89, setMatchers)));" fullword ascii
    $s18 = "getWidthOrHeight = 40, Expr = \"ipt\", on = \"Cr\", disabled = \"ons\", rmultiDash = \"Shel\";" fullword ascii
    $s19 = "getElementsByName = \"ci\", triggered = \"en\", matcher = \"A\";" fullword ascii
    $s20 = "raw[defaultView + random]();" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}