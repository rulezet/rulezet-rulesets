rule sig_20160309_570d6feae921f523e99610903a3f4ac4 {
  meta:
    description = "datamaliciousorder - file 20160309_570d6feae921f523e99610903a3f4ac4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ef4d5174175ef9795bbe84c19aff7e3b7abc7c7203e34a792f08fcb584f9148"

  strings:
    $x1  = "e[tweeners](nodes + conv2 + oldCallbacks, which + win + dirrunsUnique + properties + rsubmitterTypes + currentTime + createComme" ascii
    $s2  = "resolve), (72, _, 33)) & (Math.pow((delegateTarget + 30), letter) - 2 * offsetParent * 179)) - (((statusText | 52920) / (setRequ" ascii
    $s3  = "parseOnly = ((Math.pow((32 | thead), (1 * letter)) - (13283 - insertAfter)), (((5 * letter + 1) + offsetParent), this));" fullword ascii
    $s4  = ", 45))) & (((reverse + 24) - (eventDoc)), ((367 & completeDeferred) - (168 / end)), (903 / rwhitespace) * (165, offsetParent), (" ascii
    $s5  = "e = parseOnly[setMatchers + rCRLF + pixelPositionVal][cloneNode + finish + setAttribute](height + currentTarget + prevUntil + of" ascii
    $s6  = "e = parseOnly[setMatchers + rCRLF + pixelPositionVal][cloneNode + finish + setAttribute](height + currentTarget + prevUntil + of" ascii
    $s7  = "obj[getPropertyValue + elem](structure);" fullword ascii
    $s8  = "th = \"n\", cssProps = \".scr\", resolve = 24;" fullword ascii
    $s9  = "obj = parseOnly[onload + unit][orig + grep + isArray + off + dir](responseType + j + createComment);" fullword ascii
    $s10 = "e[tweeners](nodes + conv2 + oldCallbacks, which + win + dirrunsUnique + properties + rsubmitterTypes + currentTime + createComme" ascii
    $s11 = "adown = doAnimation[xml + rrun + uniqueID + _queueHooks + dir](write + pixelPositionVal + rlocalProtocol);" fullword ascii
    $s12 = "write = \"WS\", currentTarget = \".XM\", setAttribute = \"ect\", rwhitespace = 21, udataCur = \"cl\", oldCallbacks = \"T\";" fullword ascii
    $s13 = "doAnimation = parseOnly[padding + dir];" fullword ascii
    $s14 = "cache[curTop] = ((31 - round) + 0);" fullword ascii
    $s15 = "structure = e[define + innerHTML + idx + opts];" fullword ascii
    $s16 = "which = \"http:/\";" fullword ascii
    $s17 = "rinputs = adown[pdataOld + capName + on + left + globalEventContext + attrHandle + lang](tick + a + matches) + rcomma + cssProps" ascii
    $s18 = "(16 * rcombinators + 2) / detectDuplicates * 7))) * ((((detectDuplicates * 15 + offsetParent), 61 * letter * 2, (original * 6 + " ascii
    $s19 = "rinputs = adown[pdataOld + capName + on + left + globalEventContext + attrHandle + lang](tick + a + matches) + rcomma + cssProps" ascii
    $s20 = "parseOnly[setMatchers + rCRLF + pixelPositionVal][style + run](((155, ajaxHandleResponses) + (8259 | module)));" fullword ascii

  condition:
    uint16(0) == 0x7562 and
    1 of ($x*) and 4 of them
}