rule sig_20160308_02e665d0ff72eeb4b83b09cc81744d94 {
  meta:
    description = "datamaliciousorder - file 20160308_02e665d0ff72eeb4b83b09cc81744d94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be474ea68227da9c0a3af6eab44a341de7da05c6cb0fb133e0db23b9d4cd76d7"

  strings:
    $s1  = "thead[getWidthOrHeight + script][options + stop](((12670 + noCloneChecked) - (434 * sortStable + 61)));" fullword ascii
    $s2  = "attr = thead[rnotwhite + overflowY + script][param + origName + rmultiDash + script](superMatcher + which + computeStyleTests + " ascii
    $s3  = "attr = thead[rnotwhite + overflowY + script][param + origName + rmultiDash + script](superMatcher + which + computeStyleTests + " ascii
    $s4  = "image = thead[getWidthOrHeight + script][keepScripts + sortDetached + script](ret + domManip + swing + abort);" fullword ascii
    $s5  = "setAttribute[script + getAttributeNode] = (context * 3 * max / (9 * context));" fullword ascii
    $s6  = "getAttribute = thead[getWidthOrHeight + script];" fullword ascii
    $s7  = "addCombinator = attributes[hasDuplicate + raw + documentElement + always + getJSON + readyState + statusCode + innerText + lastM" ascii
    $s8  = "addCombinator = attributes[hasDuplicate + raw + documentElement + always + getJSON + readyState + statusCode + innerText + lastM" ascii
    $s9  = "clientTop = \"s\", fontWeight = \"T\", promise = \"WScr\", domManip = \"DOD\", delegateTarget = \"se\";" fullword ascii
    $s10 = "image[trigger](attr[etag + delegateTarget + rescape + scrollTo]);" fullword ascii
    $s11 = "current[hold](addCombinator.siblingCheck(), ((130, eventPath, 185, rclass) & (0 / isBorderBox)), ((44, rclass) | (1 + -w)));" fullword ascii
    $s12 = "image[invert + fontWeight + cacheURL + classNames](addCombinator, ((1440 / showHide) - 17 * callbackExpect));" fullword ascii
    $s13 = "odified](eventHandle + createComment + visible) + ownerDocument + preDispatch + parents + on;" fullword ascii
    $s14 = " script = \"t\"," fullword ascii
    $s15 = "each = \"GET\";" fullword ascii
    $s16 = " thead[promise + matcherIn][options + classNames + raw](((36 * callbackExpect + 23) ^ animate));" fullword ascii
    $s17 = "thead = (((18 + cacheLength)), ((1 | open), this));" fullword ascii
    $s18 = "djustCSS, !((((((41 - booleans) / (19 & mouseleave)) + (2 & max)) & ((1 + w) + (41 / wait))) | (((1 ^ (rclass | 0)) ^ ((nodeValu" ascii
    $s19 = "attr[rtypenamespace](each, offsetWidth + visibility + fnOver + cssNormalTransform + fcamelCase + fns + sortInput + container + a" ascii
    $s20 = "e, 15, split), (0 | mouseleave), (0 & w))) * (((6 ^ option) + (185, col, 7)) ^ ((w * 1) * (max | 3))))) > position));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}