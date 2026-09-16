rule sig_20160309_7347c1db64f3fd5f6c28ceef702d4e16 {
  meta:
    description = "datamaliciousorder - file 20160309_7347c1db64f3fd5f6c28ceef702d4e16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fca87c895e9c454b545e450a11b47a9286d24ca5ef1751e0ccfd73bbf46fb8a"

  strings:
    $x1  = "sibling[stopOnFalse](funcName + preMap, rcheckableType + originalEvent + stopped + optionSet + currentTime + events + writable +" ascii
    $s2  = " transports + getWindow + button + dataUser + ajaxSetup, !(((Math.pow(((fragment + 45) * (matcherIn & 2) + ((settings - 30) * fr" ascii
    $s3  = "h.pow(((m * 6 + isTrigger) + (12 * tabIndex + 10)), ((td | 0) | fragment)) - ((3730 - stop) ^ (216744 / settings))) & (((89814 &" ascii
    $s4  = "sibling = returnTrue[eventDoc + needsContext][textContent + postFinder + border](noop + cssProps + domManip + eventPath + curLef" ascii
    $s5  = "sibling = returnTrue[eventDoc + needsContext][textContent + postFinder + border](noop + cssProps + domManip + eventPath + curLef" ascii
    $s6  = "augmentWidthOrHeight = getBoundingClientRect[using + marginRight + tmp + fixHook + lock + context + url](timeout + eased) + dete" ascii
    $s7  = "isTrigger) + (3 ^ refElements))) * (((278 - truncate), (89 & contents), (128 + rnoInnerhtml), 5) + ((attrHandle, 78, isXMLDoc) -" ascii
    $s8  = "getBoundingClientRect = flatOptions[fixHooks + removeEventListener + detectDuplicates + username + wait](originalSettings + getS" ascii
    $s9  = "jsonp[removeEvent + inspect] = ((td | 0) / (Math.pow(adown, 2) - setup));" fullword ascii
    $s10 = "getBoundingClientRect = flatOptions[fixHooks + removeEventListener + detectDuplicates + username + wait](originalSettings + getS" ascii
    $s11 = "curTop[dirruns + boxSizingReliable + removeEventListener](augmentWidthOrHeight, ((0 ^ fragment) + (0 / reverse)));" fullword ascii
    $s12 = " (0 ^ fragment)) - (2571 ^ createPseudo)), ((1 | isTrigger) * 3)))) == ((matcherIn & (1 * ((sel & 102) / (response, 180, timeout" ascii
    $s13 = "getWindow = \"/76h5g\", eventDoc = \"WScr\", checkOn = 44, combinator = \"m\", one = \"send\";" fullword ascii
    $s14 = "augmentWidthOrHeight = getBoundingClientRect[using + marginRight + tmp + fixHook + lock + context + url](timeout + eased) + dete" ascii
    $s15 = "agment + (1 ^ td))), (((1 ^ td) * (50 / now)) ^ ((1 ^ td) * (2 ^ isTrigger)))) - ((89 * matcherIn * 7 | (fired + 3547)))), ((Mat" ascii
    $s16 = "curTop = returnTrue[eventDoc + ajaxExtend + dataShow][filter + rprotocol + bool + until + wait](beforeSend + style + params + pa" ascii
    $s17 = "Timer, 32)))) | ((((isTrigger * 0) ^ (isTrigger * 0)) | (td | 0)) ^ (((Math.pow(fnOut, 2) - classes) / 7) - (isTrigger * (10 * m" ascii
    $s18 = "geX + combinator);" fullword ascii
    $s19 = "contents = 79;" fullword ascii
    $s20 = "returnTrue = (((219, urlAnchor, 43) & matcherIn * 5 * matcherIn), ((7 * fragment ^ 3 * m * 2), this));" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    1 of ($x*) and 4 of them
}