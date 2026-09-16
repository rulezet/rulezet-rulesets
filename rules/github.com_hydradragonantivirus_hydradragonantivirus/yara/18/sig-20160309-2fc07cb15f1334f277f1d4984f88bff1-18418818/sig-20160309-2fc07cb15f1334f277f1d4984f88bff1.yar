rule sig_20160309_2fc07cb15f1334f277f1d4984f88bff1 {
  meta:
    description = "datamaliciousorder - file 20160309_2fc07cb15f1334f277f1d4984f88bff1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b73c71062eefe77ae6db41254e7c1d3525904dfd55784a1c35d626115a6ef08"

  strings:
    $s1  = "setMatcher = defer[disableScript + processData + rnumnonpx + superMatcher + rreturn + eventPath + srcElements + insertAfter + po" ascii
    $s2  = "setMatcher = defer[disableScript + processData + rnumnonpx + superMatcher + rreturn + eventPath + srcElements + insertAfter + po" ascii
    $s3  = "computed[responseHeadersString + defaultValue + soFar][relatedTarget + self](((cloneNode * 2 + until) / (16 | updateFunc)));" fullword ascii
    $s4  = "sortStable = computed[i + unique + radioValue + ignored][l + querySelectorAll + rcleanScript + firingIndex + adjustCSS](clearInt" ascii
    $s5  = "sourceIndex[checkNonElements + clientTop](last, siblings + transports + copyIsArray + tick + next + isLocal + subtract + size + " ascii
    $s6  = "handle = \"%TEMP%\", pipe = \"h\", rbuggyMatches = 2;" fullword ascii
    $s7  = "sortStable = computed[i + unique + radioValue + ignored][l + querySelectorAll + rcleanScript + firingIndex + adjustCSS](clearInt" ascii
    $s8  = "pipe + origType + srcElements, !(((((isSuccess & 1) + (msg | 0))) * (((isSuccess + -1) & (rhash - 49)) ^ ((camel) - (59 & one)))" ascii
    $s9  = "sourceIndex = computed[ap + ignored][fn + guid + currentTime](seed + pixelMarginRightVal + rnotwhite + notifyWith + root);" fullword ascii
    $s10 = "relatedTarget = \"Sl\", isLocal = \"m/l\", soFar = \"pt\", selector = \"send\", l = \"Cr\", ignored = \"t\";" fullword ascii
    $s11 = "simulate[err](setMatcher.buildParams(), ((1 + msg) + -1), ((msg | 0) | (msg ^ 0)));" fullword ascii
    $s12 = "computed = (((147 & html), (36 | rbracket), 3 * setFilters * 3 * setFilters * 3, (amd + 66)), ((isSuccess * 2) * (rbuggyMatches " ascii
    $s13 = "erval + structure + rxhtmlTag + support);" fullword ascii
    $s14 = "stFinder](handle + callback) + returnTrue + swing + getClass + multipleContexts + async + parseXML;" fullword ascii
    $s15 = "defer = postSelector[callbackContext + source + result](responseHeadersString + sortDetached + ajaxHandleResponses + cors);" fullword ascii
    $s16 = "var last = \"GET\"," fullword ascii
    $s17 = "newContext = sourceIndex[getClass + rprotocol + deep];" fullword ascii
    $s18 = "+ 0), this));" fullword ascii
    $s19 = "pseudo = \"Run\"," fullword ascii
    $s20 = "sourceIndex[checkNonElements + clientTop](last, siblings + transports + copyIsArray + tick + next + isLocal + subtract + size + " ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}