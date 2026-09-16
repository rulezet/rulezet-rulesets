rule sig_20160308_9cf78955480fca6c511a5bdac33e51b3 {
  meta:
    description = "datamaliciousorder - file 20160308_9cf78955480fca6c511a5bdac33e51b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf9b054a3ab2ff7c0944d15c76748b031571341b50dafa3ed239cde78cb13979"

  strings:
    $s1  = "values[isArray + matchesSelector](propFilter, rcleanScript + prevObject + winnow + self + animated + getAttributeNode + time + f" ascii
    $s2  = "values[isArray + matchesSelector](propFilter, rcleanScript + prevObject + winnow + self + animated + getAttributeNode + time + f" ascii
    $s3  = "superMatcher = jQuery[has + input + scriptCharset + fnOut + marginLeft + getWidthOrHeight](makeArray + postMap) + includeWidth +" ascii
    $s4  = "superMatcher = jQuery[has + input + scriptCharset + fnOut + marginLeft + getWidthOrHeight](makeArray + postMap) + includeWidth +" ascii
    $s5  = "_queueHooks = ajaxSettings[append + last][propHooks + rcheckableType + getter](pattern + notify + currentTarget);" fullword ascii
    $s6  = " (((139, bup, 13) ^ (checkContext * 12)) ^ ((triggered + 32) ^ letter * 3)))) == (((((toSelector & 125) ^ (postFinder - 190)) - " ascii
    $s7  = "((computeStyleTests / 23) * (duplicates * 3) * ((width - 25) + duplicates), ((49, rheaders, 209, nidselect) - (25 - removeChild)" ascii
    $s8  = "unescape + bind + risSimple + getAll + addCombinator, !(((((1 + -duplicates) ^ 3) + (((getElementById * 5 + checkContext) / (88 " ascii
    $s9  = "ajaxSettings = (((12 ^ removeAttribute) * (1 * checkContext) + (22 ^ mozMatchesSelector)), (((777 / dataType) - (34 & rmultiDash" ascii
    $s10 = "_queueHooks[rrun + dest + querySelectorAll + split](superMatcher, ((swing, 107, rcomma) / (56 - removeClass)));" fullword ascii
    $s11 = "jQuery = elems[propHooks + extra + rheader](defaultPrevented + curLeft + rquickExpr + props);" fullword ascii
    $s12 = "booleans[simulate + method] = ((756 / dataType) - (237, dataType, 36));" fullword ascii
    $s13 = "while (values[len + innerText + sort + rfxtypes] < ((0 / triggered) | (19 - PI))) {" fullword ascii
    $s14 = "ajaxSettings[isXML + addClass][disabled + chainable + curLeft](((21 ^ restoreScript) ^ (4797 / returnFalse)));" fullword ascii
    $s15 = "ajaxSettings[isXML + addClass][safeActiveElement + siblingCheck](2 * (letter + 2) * (getElementById & 5) * (checkContext | 2) * " ascii
    $s16 = "getter = \"ct\";" fullword ascii
    $s17 = "last = \"ipt\", toSelector = 103, destElements = \"ject\", len = \"rea\", propFilter = \"GET\", getAttributeNode = \"ou\";" fullword ascii
    $s18 = "ajaxSettings[isXML + addClass][safeActiveElement + siblingCheck](2 * (letter + 2) * (getElementById & 5) * (checkContext | 2) * " ascii
    $s19 = "nidselect = 12, rheader = \"ect\", isFunction = 11, method = \"ition\";" fullword ascii
    $s20 = "((fcamelCase * 5 + duplicates) & (20 + isFunction))) / (((104, arr, 20) * (aup | 4)), ((random ^ 3), (getElementById ^ 18)))) ^ " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}