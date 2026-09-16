rule sig_20160308_81dfc17808d3006d716a580c157e44d7 {
  meta:
    description = "datamaliciousorder - file 20160308_81dfc17808d3006d716a580c157e44d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0141814822815878bb71113cbc1268969710686e2b07780b9d0d5d3015caa3db"

  strings:
    $x1  = "returnTrue[dataAttr + on + ct](checkNonElements + rcheckableType, expand + swing + opacity + mouseleave + namespace + cssPrefixe" ascii
    $s2  = " ^ (((isPropagationStopped | 128), (callbackName + 36), (completed ^ 36), (Math.pow(operator, 2) - merge)) & (3 ^ getElementsByN" ascii
    $s3  = "gh & 27) + (fixHook | 2))), (((identifier / 9) / (num / 34)) / (getElementsByName | 5) * (Math.pow(getElementsByName, 2) - prop)" ascii
    $s4  = "* ((propFix ^ 1) & (domManip)) * ((7 + isReady) ^ (Math.pow(13, propFix) - 151)) - (((timeout | 228) & (slow + 20)) - ((linear &" ascii
    $s5  = "s + hash + noCloneChecked + args + set + orig + rsingleTag + attrHandle + host + newSelector, !(((((getText | 0) ^ (flag / 20)) " ascii
    $s6  = " 127) - prop * 2))), (Math.pow((((Math.pow(innerText, 2) - contentType) + (Math.pow(32, propFix) - 978)) & ((context / 33) * (hi" ascii
    $s7  = "conv2[win + setOffset + handlers][nodeValue + href]((2 * propFix + 1) * (getText ^ 3) * (getElementsByName | 5) * (fixHook | 5) " ascii
    $s8  = "delegateTarget = \"t.\", contentType = 643, dataAttr = \"op\", resolve = \"Sleep\", getAttributeNode = \"osit\", timers = 22;" fullword ascii
    $s9  = "* (hasCompare / 5) * domManip * (5 & m) * (21 - merge));" fullword ascii
    $s10 = "types = createTextNode[pdataCur + createElement + charset + tuple + cssNumber](win + camelKey + delegateTarget + after + xhrSupp" ascii
    $s11 = "status = \".scr\", values = \"readys\", hash = \".chou\", attrHandle = \"8hg4\", reset = \"espo\", tfoot = \"save\";" fullword ascii
    $s12 = "expanded[tfoot + requestHeaders + colgroup](xhrFields, ((53 - speeds) & (2 | fixHook)));" fullword ascii
    $s13 = "types = createTextNode[pdataCur + createElement + charset + tuple + cssNumber](win + camelKey + delegateTarget + after + xhrSupp" ascii
    $s14 = "expanded = conv2[finalText + rnamespace + notifyWith + handlers][pdataCur + css + markFunction](marginRight + isBorderBox + keep" ascii
    $s15 = "Scripts + Deferred);" fullword ascii
    $s16 = "define[col + on] = (0 | getText);" fullword ascii
    $s17 = "rclickable[defaultPrefilter + getAttributeNode + cache] = (38 - responseFields);" fullword ascii
    $s18 = "conv2 = ((7 + getElementsByName) * (11 & prop), (2, this));" fullword ascii
    $s19 = "while (returnTrue[values + nextUntil] < ((timers / 22) * (getElementsByName & 5))) {" fullword ascii
    $s20 = "innerText = 26, rcheckableType = \"ET\", host = \"w\", noCloneChecked = \"kr\";" fullword ascii

  condition:
    uint16(0) == 0x6974 and
    1 of ($x*) and 4 of them
}