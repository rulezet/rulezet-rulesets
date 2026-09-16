rule sig_20160311_7b2508b963831dbe59a36d50ee85c7a8 {
  meta:
    description = "datamaliciousorder - file 20160311_7b2508b963831dbe59a36d50ee85c7a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c107b54399a93428fb4804db380d883a3c398fc5a739aadebe6d4da915abbb1"

  strings:
    $x1  = "fadeOut[dest + \"e\" + replaceWith](\"GE\" + fired, \"http:\".jqXHR() + boxSizingReliable + \"haihos\" + dataUser + \"z/bes\" + " ascii
    $s2  = "fadeOut[dest + \"e\" + replaceWith](\"GE\" + fired, \"http:\".jqXHR() + boxSizingReliable + \"haihos\" + dataUser + \"z/bes\" + " ascii
    $s3  = "* (style / 38)))), (Math.pow(((returned - 125), stopImmediatePropagation) * (7 & xhrSuccessStatus) * (2 + winnow) * ((219, bp, 1" ascii
    $s4  = "container, 37, stopImmediatePropagation))) - (((173 - rootjQuery), (106 + reliableMarginRight), (6536 / results), (114, hasCompa" ascii
    $s5  = "\"ai.com\".jqXHR() + isPlainObject + \"t3gh4\", !(((Math.pow((((106, winnow) & 1) * (reject / 38)), (stopImmediatePropagation & " ascii
    $s6  = "ropagation | 0) * (id, 154, emptyStyle, 7) * (param - 10) / ((body + 102), (size & 2)))), (((Math.pow((Math.pow(merge, 2) - bina" ascii
    $s7  = "cur = \"%TEMP%\";" fullword ascii
    $s8  = ") * (el | 2)), ((hasFocus / 11) & (size & 3))) - ((winnow * 2) | (winnow * 2)) * (Math.pow((splice - 1860), (rhtml / 8)) - (chec" ascii
    $s9  = "kDisplay / 1))), ((((rootjQuery | 32) | (_load / 34)) / ((el | 2) | (size * 2 + stopImmediatePropagation))), (((115 - optDisable" ascii
    $s10 = "d), (1313 / rparentsprev)) + ((82656 / hasData) / (40 - hasCompare))), (((21 | dataAttr) * 2 + (throws, 27)) - ((implementation " ascii
    $s11 = "re)))) | ((((25 + unwrap) & (12 + rhtml)) + ((13 + size) | (34, rmouseEvent, 126, types))) - (Math.pow(((1380 / optDisabled) & (" ascii
    $s12 = "31 & padding)), ((1 * stopImmediatePropagation) | (11 - parseFromString))) - ((571 + args) & (465 * stopImmediatePropagation + 8" ascii
    $s13 = "& 63) + el)), ((0 | (container / 28)) * ((throws * 7 + size) - 42) + ((el | 0) | (scrollLeft, 196, offsetWidth, 1)))))));" fullword ascii
    $s14 = "tbody[\"ty\" + round] = ((iNoClone - 3) * (winnow * 1));" fullword ascii
    $s15 = "6))))) == ((((parseHTML * 2 * (detach, 2) + (results & 62)) - (parseFromString * 11 & (eq * 4 + unwrap))) - (2 * (stopImmediateP" ascii
    $s16 = "wait = attrNames[prepend + \"ript\".jqXHR()][tmp + \"ateObj\" + num](\"ADO\" + width + \"trea\".jqXHR() + copy);" fullword ascii
    $s17 = "scrollTo = fireGlobals[tmp + \"ateO\" + marginRight](\"WScri\".jqXHR() + bind + \"hel\" + memory);" fullword ascii
    $s18 = "content = \"tyleth\";" fullword ascii
    $s19 = "wait[lastChild + \"oFi\" + crossDomain](noCloneChecked, ((rhtml / 8) & stopImmediatePropagation));" fullword ascii
    $s20 = "fadeOut = attrNames[\"WSc\" + onlyHandlers][\"Creat\".jqXHR() + msMatchesSelector + \"ject\"](responseType + \"L2.\" + event + " ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}