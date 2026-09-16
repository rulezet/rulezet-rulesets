rule sig_20160308_5cd720b8c70b96a4aeb1c2afc404c772 {
  meta:
    description = "datamaliciousorder - file 20160308_5cd720b8c70b96a4aeb1c2afc404c772.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5dd6eb9f96586ea4f2426e7fd160f385f0bca6782b804fd15cf70b04d5de375b"

  strings:
    $x1  = "getText[rscriptTypeMasked](escapedWhitespace, setter + preventDefault + markFunction + noCloneChecked + proxy + clientTop + not " ascii
    $s2  = "get[content] = ((0 ^ nativeStatusText) - (124 - createDocumentFragment));" fullword ascii
    $s3  = "rt)) - (733305 & _data)) / ((4 + temp) & (11 & originalEvent)))), ((Math.pow(((1 + lang) + (26 * clientX + 7)), ((etag, 138, foc" ascii
    $s4  = "fontWeight = compiled[modified + slideToggle + password + defaultPrevented + s + firstDataType + classes + propFix + clearQueue]" ascii
    $s5  = "tById + 137)), (attrs ^ 0)) - ((Math.pow(close, 2) - keyHooks) & (4095 & rmultiDash))), ((Math.pow((985 & push_native), (64 / so" ascii
    $s6  = "cleanData[scriptCharset + css + _queueHooks + cssExpand](fontWeight, ((3 * unmatched) - (Math.pow(42, attrs) - 1712)));" fullword ascii
    $s7  = "cleanData[pipe](getText[bySet + nodeType + rbracket]);" fullword ascii
    $s8  = "before) / (8 ^ b)) & (2 * margin * (1 * attrs) + (8 ^ DOMParser))), (Math.pow((Math.pow((62 & support), (0 | attrs)) - (161 * ge" ascii
    $s9  = "getText[rscriptTypeMasked](escapedWhitespace, setter + preventDefault + markFunction + noCloneChecked + proxy + clientTop + not " ascii
    $s10 = "interval[matcherFromGroupMatchers + token + pnum][last + sortDetached](((4563 / safeActiveElement) & (96 | getById)));" fullword ascii
    $s11 = "fontWeight = compiled[modified + slideToggle + password + defaultPrevented + s + firstDataType + classes + propFix + clearQueue]" ascii
    $s12 = "ative, 2) - nextSibling), (15032 & delay)));" fullword ascii
    $s13 = "interval[matcherFromGroupMatchers + writable][last + sortDetached](((97 - subtract), (58, classCache, 113), (Math.pow(leadingRel" ascii
    $s14 = "while (getText[then + conditionFn + pnum + cssExpand] < ((87 ^ guaranteedUnique) / (40 & copy))) {" fullword ascii
    $s15 = "getText = interval[rjsonp + insertBefore][hidden + isXML + preexisting](push + unwrap + pop + attrNames);" fullword ascii
    $s16 = "password = \"n\"," fullword ascii
    $s17 = "interval = (((147 ^ serializeArray), (250 - e)), (((0 ^ focusin) * (44 / matchedCount)), this));" fullword ascii
    $s18 = " (15504 / optall))) - (((40, rdisplayswap, 226, winnow) / (28 - prepend)) / ((69 - clientY) & (16 + scrollTo))))) == (((((379 + " ascii
    $s19 = "originalSettings)) / ((47 - size), 2 * size * 2 * attrs))))));" fullword ascii
    $s20 = "current[cssNormalTransform + prependTo] = ((5 - clientX) * (102, statusText, 227, disconnectedMatch));" fullword ascii

  condition:
    uint16(0) == 0x6144 and
    1 of ($x*) and 4 of them
}