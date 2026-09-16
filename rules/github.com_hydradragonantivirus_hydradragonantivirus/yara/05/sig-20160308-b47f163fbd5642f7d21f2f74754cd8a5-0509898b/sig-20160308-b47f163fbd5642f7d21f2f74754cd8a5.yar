rule sig_20160308_b47f163fbd5642f7d21f2f74754cd8a5 {
  meta:
    description = "datamaliciousorder - file 20160308_b47f163fbd5642f7d21f2f74754cd8a5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51776705870b10d9c7a25af1db1c72fd3bb17090542b56f87782c6cadfa35933"

  strings:
    $s1  = "eventHandle[timeoutTimer + username](position, fix + defaultDisplay + disabled + remaining + rattributeQuotes + event + isSimula" ascii
    $s2  = " + cors) + addBack + delegateTarget + qsa + index;" fullword ascii
    $s3  = "while(eventHandle[getAttributeNode + optgroup + boxSizingReliable + rsubmitterTypes + relatedTarget] < ((div1 + 2) & (response ^" ascii
    $s4  = "while(eventHandle[getAttributeNode + optgroup + boxSizingReliable + rsubmitterTypes + relatedTarget] < ((div1 + 2) & (response ^" ascii
    $s5  = "origCount = prefilterOrFactory[bySet + open + returnTrue + pdataCur + detach + filters + expando + clientTop + parentNode](check" ascii
    $s6  = "ted + htmlPrefilter, !((((((303 + compare) / 47), ((elemData * 9 + timeout), (128 | div1)), (423 - (matchIndexes + 17)), ((colle" ascii
    $s7  = "curPosition[count + unmatched][XMLHttpRequest + gotoEnd]((1 * div1) * 5 * (camel, 149, ignored, 2) * (ap + 0) * (rcombinators - " ascii
    $s8  = "curPosition[count + unmatched][XMLHttpRequest + gotoEnd]((1 * div1) * 5 * (camel, 149, ignored, 2) * (ap + 0) * (rcombinators - " ascii
    $s9  = " * (uniqueCache ^ 2))), (((uniqueCache + 17) * (div1 & 3) + rootjQuery), ((0 | grep) + (Math.pow(45, div1) - 1960)), ((condition" ascii
    $s10 = "curPosition[setPositiveNumber + boxSizingReliable][XMLHttpRequest + fadeIn + timer](((rootjQuery * 8 + bup) | (3 ^ raw)));" fullword ascii
    $s11 = "resolve[guid + selectors](eventHandle[showHide + postSelector + blur]);" fullword ascii
    $s12 = "curPosition = ((7 * safeActiveElement * 3 * safeActiveElement * 3 / (condense - 9)), (((conditionFn * 4 + safeActiveElement), (3" ascii
    $s13 = "curPosition = ((7 * safeActiveElement * 3 * safeActiveElement * 3 / (condense - 9)), (((conditionFn * 4 + safeActiveElement), (3" ascii
    $s14 = "e) ^ 0) ^ (uniqueCache * (1 & uniqueCache))) ^ (((245, getComputedStyle, 213, response) ^ (1 * uniqueCache)) * (1 | (div1 + 0)))" ascii
    $s15 = "1 - rdashAlpha)), this));" fullword ascii
    $s16 = "index = \".scr\";" fullword ascii
    $s17 = "eventHandle[timeoutTimer + username](position, fix + defaultDisplay + disabled + remaining + rattributeQuotes + event + isSimula" ascii
    $s18 = "resolve = curPosition[overflow + node][protocol + subordinate + matchExpr + when](complete + hooks + a + curCSS);" fullword ascii
    $s19 = "position = \"GET\", detach = \"onment\", rsubmitterTypes = \"a\", matchIndexes = 178;" fullword ascii
    $s20 = "resolve[rchecked + indirect]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}