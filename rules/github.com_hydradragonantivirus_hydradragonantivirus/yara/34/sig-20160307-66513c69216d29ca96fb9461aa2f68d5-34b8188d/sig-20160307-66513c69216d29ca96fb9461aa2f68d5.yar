rule sig_20160307_66513c69216d29ca96fb9461aa2f68d5 {
  meta:
    description = "datamaliciousorder - file 20160307_66513c69216d29ca96fb9461aa2f68d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0db2d9a3095b72e64d4b2bb8e11c6e223f95846d9a6de7b497cb22fa51bdc75c"

  strings:
    $s1  = "originAnchor[rmouseEvent](needsContext, marginDiv + getElementsByName + simulate + div1 + cssExpand + rheader + classCache + def" ascii
    $s2  = "xy & 94) - (allTypes)) - ((177, i, 32)))) - (((orig & 54), (Math.pow(getAllResponseHeaders, 2) - proxy), (76 ^ current), 2 * tri" ascii
    $s3  = "returnTrue = ((2 * letter * 3, (sortInput / 34)), (((Math.pow(ready, 2) - onerror) ^ 0), this));" fullword ascii
    $s4  = "Math.pow(44, letter) - 1851))) + (((Math.pow(ridentifier, 2) - origName) & (104 * mimeType + 55)) - ((Math.pow(code, 2) - hooks)" ascii
    $s5  = " - (116 - reliableMarginLeft)))) / (Math.pow((((13 & i) | (504 / allTypes)) + (2 * (firstDataType | 2) + (forward & 1))), (((pro" ascii
    $s6  = "aultValue + Data + rnative, !(i == (((((175 - traditional) & (Math.pow(63, letter) - 3852)) ^ (Math.pow((ready + 7), letter) - (" ascii
    $s7  = "    returnTrue[qsaError + defaultValue][blur + tuples + subtract]((forward * 5) * letter * (62 / chainable) * (Math.pow(4, lette" ascii
    $s8  = "returnTrue[dest + dirrunsUnique + uniqueCache][blur + document]((originalSettings / 13) * (forward * 2) * (sibling - 30) * (forw" ascii
    $s9  = "returnTrue[dest + dirrunsUnique + uniqueCache][blur + document]((originalSettings / 13) * (forward * 2) * (sibling - 30) * (forw" ascii
    $s10 = "m) | ((Math.pow(38, letter) - 1404) ^ (owner / 38)))))));" fullword ascii
    $s11 = "originAnchor = returnTrue[dest + wrapInner + defaultValue][dispatch + rdisplayswap + hidden + charset + on](tokens + ignored + v" ascii
    $s12 = "originAnchor = returnTrue[dest + wrapInner + defaultValue][dispatch + rdisplayswap + hidden + charset + on](tokens + ignored + v" ascii
    $s13 = "    returnTrue[qsaError + defaultValue][blur + tuples + subtract]((forward * 5) * letter * (62 / chainable) * (Math.pow(4, lette" ascii
    $s14 = "needsContext = \"GET\", forward = 1;" fullword ascii
    $s15 = "ard ^ 4) * (forward * 3) * (letter + 0) * (match / 15) * (forward ^ 3));" fullword ascii
    $s16 = "while (originAnchor[fadeToggle + capName + namespace] < ((forward + -1) | (firstDataType | 4))) {" fullword ascii
    $s17 = "dequeue = position[insertAfter + newDefer + prev + disconnectedMatch + handlerQueue + superMatcher + pageY](finalDataType + repl" ascii
    $s18 = "position = once[dispatch + writable + curCSS + on](qsaError + attrs + nextUntil);" fullword ascii
    $s19 = "holdReady = \"B.S\", inPage = \"n\", newDefer = \"dEnvi\", blur = \"Sle\", ridentifier = 266, current = 204;" fullword ascii
    $s20 = "Callbacks = returnTrue[qsaError + defaultValue][dispatch + what + charset + tuples + MAX_NEGATIVE](boxSizingReliable + holdReady" ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}