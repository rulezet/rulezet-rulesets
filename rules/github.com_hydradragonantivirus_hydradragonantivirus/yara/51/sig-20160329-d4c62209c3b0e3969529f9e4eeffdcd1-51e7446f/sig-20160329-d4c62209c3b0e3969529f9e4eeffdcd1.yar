rule sig_20160329_d4c62209c3b0e3969529f9e4eeffdcd1 {
  meta:
    description = "datamaliciousorder - file 20160329_d4c62209c3b0e3969529f9e4eeffdcd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9f6e3793a794a194ec7613055d427d563bf1827bda65f1373519f439adf8742"

  strings:
    $s1  = "cssPrefixes[getElementById + \"ript\"][letter](((Math.pow(pixelPositionVal, 2) - v) & (2042 * cloneCopyEvent + 924)));" fullword ascii
    $s2  = "newContext[cloneNode + \"pt\"][colgroup + \"leep\"](((1659 & parsed) + (3427 - compare)));" fullword ascii
    $s3  = "replaceWith(\"while%20%28oldCache%5B%22ready%22%20+%20nextUntil%20+%20%22te%22%5D%20%21%3D%20%28Math.pow%28%28cloneCopyEvent%7C3" ascii
    $s4  = "defaultPrevented[copy + \"File\"](left, (2 | (clearCloneStyle - 9)));" fullword ascii
    $s5  = "function getAllResponseHeaders() {" fullword ascii
    $s6  = "scrollTo[\"R\" + dequeue + \"n\"](left);" fullword ascii
    $s7  = "defaultPrevented[defaultValue + \"yp\" + returned] = ((1 | propName) + 0);" fullword ascii
    $s8  = "oldCache[\"se\" + token]();" fullword ascii
    $s9  = "nonce(updateFunc, createElement, before, compare, dataFilter);" fullword ascii
    $s10 = "replaceWith(\"while%20%28oldCache%5B%22ready%22%20+%20nextUntil%20+%20%22te%22%5D%20%21%3D%20%28Math.pow%28%28cloneCopyEvent%7C3" ascii
    $s11 = "cacheURL(handler, cssText, hasContent);" fullword ascii
    $s12 = "getAllResponseHeaders(letter, cloneCopyEvent, addClass, copy, addClass);" fullword ascii
    $s13 = "function accepts() {" fullword ascii
    $s14 = "function string() {" fullword ascii
    $s15 = "function disconnectedMatch() {" fullword ascii
    $s16 = "replaceWith(\"left%20%3D%20scrollTo%5B%22Expan%22%20+%20cur%20+%20%22onme%22%20+%20parseFromString%20+%20%22tri%22%20+%20open%5D" ascii
    $s17 = "for (_evalUrl = (original | (0 | original)); _evalUrl < closest[\"length\"]; _evalUrl++) {" fullword ascii
    $s18 = "replaceWith(\"left%20%3D%20scrollTo%5B%22Expan%22%20+%20cur%20+%20%22onme%22%20+%20parseFromString%20+%20%22tri%22%20+%20open%5D" ascii
    $s19 = "function replaceWith(propFix) {" fullword ascii
    $s20 = "outermost(slow, defaultValue, pixelPositionVal, open);" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}