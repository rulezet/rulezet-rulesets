rule sig_20160309_474d636e7956afbefd696c18fea099fc {
  meta:
    description = "datamaliciousorder - file 20160309_474d636e7956afbefd696c18fea099fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c842ad0f8138961cbfc0ee77f34f32617d1882fef0373c214feb723ad839ded"

  strings:
    $s1  = "hasCompare[active + beforeSend](deep, parentOffset + onload + sourceIndex + window + send + matchExpr + event + slideToggle + by" ascii
    $s2  = "lientY, 880) ^ (Math.pow(target, 2) - accepts)) / ((8 | state) + (2 * rootjQuery + 1)))))));" fullword ascii
    $s3  = "hasCompare = genFx[firingIndex + pdataOld + rsingleTag][locked + interval + swap](getById + cssHooks + stop + outermost);" fullword ascii
    $s4  = "valueIsBorderBox[s + obj + abort] = ((Math.pow(newSelector, 2) - th), (40 - valueParts));" fullword ascii
    $s5  = "target = 144;" fullword ascii
    $s6  = "hasCompare[ridentifier + beforeSend + send]();" fullword ascii
    $s7  = "genFx = ((4 + clearInterval) * (2 ^ refElements) * (6 ^ eq), (((23 - boxSizingReliable)), this));" fullword ascii
    $s8  = "Set + split + camelKey + xhr + srcElements + rbuggyMatches + rsingleTag, !(3 == (((((resolveValues ^ 705) / (checkNonElements - " ascii
    $s9  = "original = hasCompare[clientTop + specialEasing + removeProp + parents + markFunction];" fullword ascii
    $s10 = "hasCompare[active + beforeSend](deep, parentOffset + onload + sourceIndex + window + send + matchExpr + event + slideToggle + by" ascii
    $s11 = "deep = \"GET\"," fullword ascii
    $s12 = "getClass[stopped + closest] = ((0 ^ refElements) ^ (0 | refElements));" fullword ascii
    $s13 = "querySelectorAll = genFx[adown + triggered + rsingleTag];" fullword ascii
    $s14 = "namespaces[returnValue + abort](original);" fullword ascii
    $s15 = "beforeunload = rnoInnerhtml[token + css + prevObject + timerId + tbody + init + hide + beforeSend + callbackName](elementMatcher" ascii
    $s16 = "beforeunload = rnoInnerhtml[token + css + prevObject + timerId + tbody + init + hide + beforeSend + callbackName](elementMatcher" ascii
    $s17 = "refElements = 0, transports = 158, split = \"ystem\", tweener = \"Cr\", pointerenter = 157;" fullword ascii
    $s18 = "token = \"Exp\"," fullword ascii
    $s19 = "firingIndex = \"WScr\", camelKey = \"/\", type = \"Run\";" fullword ascii
    $s20 = "locked = \"Crea\";" fullword ascii

  condition:
    uint16(0) == 0x6878 and
    8 of them
}