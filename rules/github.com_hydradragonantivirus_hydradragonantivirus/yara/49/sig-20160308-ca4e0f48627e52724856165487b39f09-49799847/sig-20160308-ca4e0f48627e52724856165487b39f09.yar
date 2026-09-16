rule sig_20160308_ca4e0f48627e52724856165487b39f09 {
  meta:
    description = "datamaliciousorder - file 20160308_ca4e0f48627e52724856165487b39f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ca84aacecf78031664fb9d89d2b4ea8b0fa7d043264f00bcc513548e833bbd1"

  strings:
    $s1  = "last[outermostContext](pattern.timeout(), ((radioValue ^ 0) ^ (radioValue | 0)), ((createTextNode - 70), (Math.pow(result, 2) - " ascii
    $s2  = "cssProps = notify[srcElements + getAttribute + checkbox + namespaces + curElem](results + on + readyList);" fullword ascii
    $s3  = "ple + udataOld + optall + timer, !(createOptions == ((((1 / createOptions) ^ 0) + (ownerDocument * 2 * pseudos * 3 - (Math.pow(s" ascii
    $s4  = "trim[get + selected + curCSSTop + doAnimation + curElem][useCache + readyList + fadeTo](((4841 + rscriptTypeMasked) / (24 ^ sel)" ascii
    $s5  = "trim[get + selected + curCSSTop + doAnimation + curElem][useCache + readyList + fadeTo](((4841 + rscriptTypeMasked) / (24 ^ sel)" ascii
    $s6  = "last[outermostContext](pattern.timeout(), ((radioValue ^ 0) ^ (radioValue | 0)), ((createTextNode - 70), (Math.pow(result, 2) - " ascii
    $s7  = "trim = ((179 - (rbracket ^ 24)), (((XMLHttpRequest - 34) + (radioValue & 0)), this));" fullword ascii
    $s8  = "contains[closest](parseJSON + computed, flatOptions + elemdisplay + extend + calculatePosition + disconnectedMatch + hookFn + tu" ascii
    $s9  = "while (contains[origName + flag] < ((8 - gotoEnd) ^ (48 - rreturn))) {" fullword ascii
    $s10 = "getAttribute = \"eate\", origName = \"read\", dataTypes = (function Object.prototype.timeout() {" fullword ascii
    $s11 = "topped, 2) - createFxNow))) ^ ((1 + -(createOptions | 0)) ^ (radioValue | (1 + -createOptions))))));" fullword ascii
    $s12 = "pattern = cssProps[createHTMLDocument + statusCode + camel + content + boxSizingReliableVal + structure + nextSibling + onlyHand" ascii
    $s13 = "contains = trim[dataTypes + eventPath + memory][p + hover + progressContexts + curElem](offsetParent + button + readyWait + maxI" ascii
    $s14 = "compare[height + sortDetached + fireWith + handle](pattern, (2 * simulate * 3 / (state & 39)));" fullword ascii
    $s15 = "trim[eventHandle + doAnimation + curElem][clazz](((9309 * ownerDocument + 7415) - (isLocal + 9076)));" fullword ascii
    $s16 = "compare[clearInterval + sortDetached]();" fullword ascii
    $s17 = "contains = trim[dataTypes + eventPath + memory][p + hover + progressContexts + curElem](offsetParent + button + readyWait + maxI" ascii
    $s18 = "compare[createPseudo + sortDetached](contains[matcherFromGroupMatchers + firing + accepts + push]);" fullword ascii
    $s19 = "compare = trim[slideDown + runescape][rnamespace + curCSSTop + tfoot + response + curElem](promise + dirrunsUnique + rnotwhite);" ascii
    $s20 = "rscriptTypeMasked = 59, accepts = \"eBod\", button = \"XML2.\", simulate = 13;" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}