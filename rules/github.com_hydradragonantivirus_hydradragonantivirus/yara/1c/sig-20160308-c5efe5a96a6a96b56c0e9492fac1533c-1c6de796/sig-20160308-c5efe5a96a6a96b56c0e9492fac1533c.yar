rule sig_20160308_c5efe5a96a6a96b56c0e9492fac1533c {
  meta:
    description = "datamaliciousorder - file 20160308_c5efe5a96a6a96b56c0e9492fac1533c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad3310d008b528a39a0dbb727414cdc819dcb65ba8974d4293a3e1a017e866c3"

  strings:
    $s1  = "timeout = fragment[unmatched + bubbleType + matched][rscriptType + guaranteedUnique + ret](targets + isPlainObject + getAttribut" ascii
    $s2  = "timeout = fragment[unmatched + bubbleType + matched][rscriptType + guaranteedUnique + ret](targets + isPlainObject + getAttribut" ascii
    $s3  = "timeout[andSelf](prefix, tokenize + addEventListener + isDefaultPrevented + wait + onlyHandlers + elementMatchers + pointerleave" ascii
    $s4  = "firingIndex = urlAnchor[padding + onlyHandlers + evt + postFinder + onlyHandlers + scrollTop](restoreScript + preFilter + newUnm" ascii
    $s5  = "firingIndex = urlAnchor[padding + onlyHandlers + evt + postFinder + onlyHandlers + scrollTop](restoreScript + preFilter + newUnm" ascii
    $s6  = "rheaders[timer](allTypes.resolveValues(), ((uniqueCache / 49)), ((disableScript + 0) + -(disableScript & 1)));" fullword ascii
    $s7  = " + selected + noConflict + cssShow + headers, !(runescape == ((((40 / original) + (0 | uniqueCache)) * ((163, bool, 45) - (keys " ascii
    $s8  = "stopQueue[count + ridentifier] = ((testContext & 9) - (not - 56));" fullword ascii
    $s9  = "timeout[andSelf](prefix, tokenize + addEventListener + isDefaultPrevented + wait + onlyHandlers + elementMatchers + pointerleave" ascii
    $s10 = "fragment[cacheLength + eq][implicitRelative]((runescape + 0) * (responseContainer + 1) * (runescape & 3) * (Math.pow(statusCode," ascii
    $s11 = "fragment = (((82 ^ scrollLeft) * (2 | statusCode) + 2 * runescape * 3), (((inspectPrefiltersOrTransports / 34) ^ (contains - 24)" ascii
    $s12 = "fragment = (((82 ^ scrollLeft) * (2 | statusCode) + 2 * runescape * 3), (((inspectPrefiltersOrTransports / 34) ^ (contains - 24)" ascii
    $s13 = "allTypes = firingIndex[pop + unwrap + etag + show + parents + removeChild](responseType + getWidthOrHeight + prepend + submit + " ascii
    $s14 = "allTypes = firingIndex[pop + unwrap + etag + show + parents + removeChild](responseType + getWidthOrHeight + prepend + submit + " ascii
    $s15 = "wrap) + animation + dispatch + get + random;" fullword ascii
    $s16 = "matcherIn[qualifier + readyWait]();" fullword ascii
    $s17 = "fragment[cacheLength + eq][implicitRelative]((runescape + 0) * (responseContainer + 1) * (runescape & 3) * (Math.pow(statusCode," ascii
    $s18 = "pop = \"Expand\", querySelectorAll = \"eBody\", dataUser = \"d\", andSelf = \"open\", keys = 35, unwrap = \"Envir\";" fullword ascii
    $s19 = "matcherIn = fragment[prop + jsonProp + eq][createFxNow + eq + outerCache + postFinder + onlyHandlers + scrollTop](fire + request" ascii
    $s20 = "matcherIn = fragment[prop + jsonProp + eq][createFxNow + eq + outerCache + postFinder + onlyHandlers + scrollTop](fire + request" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}