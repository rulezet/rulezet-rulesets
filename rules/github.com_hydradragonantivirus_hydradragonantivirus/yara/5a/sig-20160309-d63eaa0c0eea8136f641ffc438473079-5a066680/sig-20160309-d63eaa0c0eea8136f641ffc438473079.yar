rule sig_20160309_d63eaa0c0eea8136f641ffc438473079 {
  meta:
    description = "datamaliciousorder - file 20160309_d63eaa0c0eea8136f641ffc438473079.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1487584211f7cf44b1f914968cd7e293c06616165c9f3a805bd38940fed6a318"

  strings:
    $s1  = "firingIndex = getClass[reliableMarginRight + slideUp + keys + compare + defineProperty + delegateTarget + isBorderBox + isArray " ascii
    $s2  = "step[keyCode](tr + genFx, udataCur + speeds + constructor + access + speed + hidden + initial + copyIsArray + calculatePosition " ascii
    $s3  = "getClass = keepScripts[fromCharCode + attrId + ontype](newSelector + offsetWidth + version + exports);" fullword ascii
    $s4  = "tweener = (((33 ^ matcherFromTokens) ^ (3432 / valueIsBorderBox)), ((Math.pow((19 + guaranteedUnique), (2 + guaranteedUnique)) -" ascii
    $s5  = "firingIndex = getClass[reliableMarginRight + slideUp + keys + compare + defineProperty + delegateTarget + isBorderBox + isArray " ascii
    $s6  = "Prevented) / (35 & clientLeft)) + ((0 | size), (2 * xhr))) - (Math.pow(((24 + rmouseEvent) - (53 & readyWait)), ((4 | overflowX)" ascii
    $s7  = "tweener[on + a + fadeToggle][delegateTarget + timeStamp](((targets * 2 + isXML) * 3 + hasOwnProperty * 29 * when));" fullword ascii
    $s8  = "tr = \"G\", speed = \"/\", targets = 1778, reliableMarginRight = \"Expand\", overflowX = 33, mappedTypes = \"Run\";" fullword ascii
    $s9  = "step = tweener[radioValue + nType + beforeSend][load + getElementsByTagName + bind + matchedCount](random + getAll + defaultDisp" ascii
    $s10 = "step = tweener[radioValue + nType + beforeSend][load + getElementsByTagName + bind + matchedCount](random + getAll + defaultDisp" ascii
    $s11 = "curLeft[matchIndexes](firingIndex.rejectWith(), (0 & response), ((327 - rrun), (1 * guaranteedUnique)));" fullword ascii
    $s12 = "/ ((response * (1 | scrollTop)) * (Math.pow((3 ^ xhr), (2 + guaranteedUnique)) - (48, responseContainer)))) ^ ((((3920 / default" ascii
    $s13 = "+ ownerDocument](disableScript + idx + speed) + clearCloneStyle + pattern + ownerDocument + scrollTo + createTween;" fullword ascii
    $s14 = "remove = tweener[scale + now + val + nType + beforeSend][load + siblings + cloneNode](unit + addGetHookIf + booleans + fnOver + " ascii
    $s15 = "+ attrs + postSelector, !(((((77 / urlAnchor) + (16 ^ guaranteedUnique)) / ((9 ^ simple) | 23)) * (((shift & 24) + (cssNormalTra" ascii
    $s16 = "remove[rnoContent + noop + check](firingIndex, (response * 2));" fullword ascii
    $s17 = "access = \"om\", load = \"Cre\", dirrunsUnique = \"Resp\", hidden = \"system\";" fullword ascii
    $s18 = "step[keyCode](tr + genFx, udataCur + speeds + constructor + access + speed + hidden + initial + copyIsArray + calculatePosition " ascii
    $s19 = "preFilter = step[dirrunsUnique + documentElement + opts + lastModified];" fullword ascii
    $s20 = "select[pageX + curElem + rscriptTypeMasked + hasClass] = (0 | (guaranteedUnique ^ 0));" fullword ascii

  condition:
    uint16(0) == 0x6461 and
    8 of them
}