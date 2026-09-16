rule sig_20160307_62b66cdd0c5954dbece0b8c0c5ed4023 {
  meta:
    description = "datamaliciousorder - file 20160307_62b66cdd0c5954dbece0b8c0c5ed4023.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeb685703c523c5908ed76cd575619a99680954264224fb3ff186c0044d105ad"

  strings:
    $s1  = "pipe[completeDeferred + hasCompare][rtagName]((Math.pow((Math.pow(68, firstDataType) - 4535), (firstDataType | 0)) - globalEvent" ascii
    $s2  = "pipe[completeDeferred + hasCompare][rtagName]((Math.pow((Math.pow(68, firstDataType) - 4535), (firstDataType | 0)) - globalEvent" ascii
    $s3  = "insertBefore = pipe[MAX_NEGATIVE + setMatcher][fire + nextUntil + getScript + clientX](cssNumber + converters + cached + unit + " ascii
    $s4  = "insertBefore = pipe[MAX_NEGATIVE + setMatcher][fire + nextUntil + getScript + clientX](cssNumber + converters + cached + unit + " ascii
    $s5  = "event[inArray](elems, radio + propFix + newUnmatched + matcherFromGroupMatchers + offsetParent + fns, !((((((len * 5 + firstData" ascii
    $s6  = "pipe[dispatch + clientX][scrollTop + isFunction](((username / 49) & (Math.pow(clearInterval, 2) - cache)));" fullword ascii
    $s7  = "transport[addEventListener + clientX + genFx] = (1 + -head);" fullword ascii
    $s8  = "event = pipe[completeDeferred + hasCompare][fire + uniqueID + getComputedStyle](max + writable + eased + setDocument);" fullword ascii
    $s9  = "pipe = (2, (((ajax ^ 2) - (has - 16)), this));" fullword ascii
    $s10 = "relatedTarget = \"veTo\", radio = \"htt\", handler = 21, write = \"i\", cssNumber = \"A\", hasCompare = \"pt\";" fullword ascii
    $s11 = "^ 89))) / (((firingIndex / 24) - (clazz & 63)) | ((speed + 5)))) / (((head * 2) * (visible, 2) * (checkOn / 28) * firstDataType " ascii
    $s12 = "* (4 ^ globalEventContext) * (1 ^ globalEventContext) / ((1 * attachEvent) * (5 - defer))) ^ ((114 / implicitRelative) * (4 | gl" ascii
    $s13 = "getScript = \"Objec\", offsetParent = \"g/98h7\", resolveWith = \"ngs\", reset = \"wri\", MAX_NEGATIVE = \"WScr\", rsingleTag = " ascii
    $s14 = "rparentsprev = pipe[matchIndexes + deep + clientX];" fullword ascii
    $s15 = "last[rsingleTag] = (1 * head);" fullword ascii
    $s16 = "fadeToggle = unique[optionSet + responseContainer + crossDomain + prependTo + write + register + camel + write + resolveWith](co" ascii
    $s17 = "Type) | (17 | push_native)), ((114 & isXML) | (187 - activeElement)), ((24 ^ checked) | (1962 / attrHooks)), (2479 - (curOffset " ascii
    $s18 = "while(event[ajaxHandleResponses + dataUser] < ((2 * firstDataType) & (4 + firstDataType))) {" fullword ascii
    $s19 = "unique = rparentsprev[unqueued + submit + complete + sel + isArrayLike](escapedWhitespace + which + replaceWith + xhrSupported);" ascii
    $s20 = "time[getElementsByTagName](fadeToggle.DOMParser(), ((0 / handler) ^ (0 ^ defer)), 0);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}