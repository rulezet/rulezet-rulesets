rule sig_20160308_bd50208f5d26d38261b1587aae9d375e {
  meta:
    description = "datamaliciousorder - file 20160308_bd50208f5d26d38261b1587aae9d375e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a68a884e2c0e7e7a34a5fbac56c89a08ebcf6cf1adf04e5b4bd5f536a44a6bb3"

  strings:
    $s1  = "while(stored[contentType + getElementsByClassName + ontype] < ((Math.pow(48, preFilter) - 2236), (compiled / 36), (Math.pow(cont" ascii
    $s2  = "while(stored[contentType + getElementsByClassName + ontype] < ((Math.pow(48, preFilter) - 2236), (compiled / 36), (Math.pow(cont" ascii
    $s3  = "handlerQueue[uniqueSort](compare.getResponseHeader(), ((10 + preexisting), 2 * preFilter * 61, (Math.pow(isArrayLike, 2) - nodeN" ascii
    $s4  = "handlerQueue[uniqueSort](compare.getResponseHeader(), ((10 + preexisting), 2 * preFilter * 61, (Math.pow(isArrayLike, 2) - nodeN" ascii
    $s5  = "stored[headers + cors](matchedCount, firing + createPseudo + matched + keyHooks + image + dataShow + newContext + getComputedSty" ascii
    $s6  = "compare = clazz[bp + selection + selectors + relatedTarget + css + maxWidth + insertAfter](firingIndex + list) + shift + createT" ascii
    $s7  = "compare = clazz[bp + selection + selectors + relatedTarget + css + maxWidth + insertAfter](firingIndex + list) + shift + createT" ascii
    $s8  = "stored[headers + cors](matchedCount, firing + createPseudo + matched + keyHooks + image + dataShow + newContext + getComputedSty" ascii
    $s9  = "(condense / 12) - (extra ^ 52)))) & (((ajaxSetup / 2) - (updateFunc * 2 + extra)) / (Math.pow((Math.pow(31, preFilter) - 922), p" ascii
    $s10 = "soFar[insertAfter + inArray + andSelf](compare, ((fx - 3) & contexts));" fullword ascii
    $s11 = "type = 2151, getComputedStyle = \"099o\", success = \"Respo\", bp = \"Expa\", addEventListener = 111, conv2 = \"clos\";" fullword ascii
    $s12 = "extra = 22, head = \"A\", eventDoc = \"posi\", relatedTarget = \"mentSt\";" fullword ascii
    $s13 = "clazz = max[test + rtagName + getClientRects + clearTimeout](a + attr + rfxtypes + beforeSend);" fullword ascii
    $s14 = "ame), 0), ((pixelPositionVal * 0) / (unique - 20)));" fullword ascii
    $s15 = "soFar = callbackContext[context + source][isReady + location + clearTimeout](head + load + disabled + simulate + first);" fullword ascii
    $s16 = "firing = \"http\", beforeSend = \"Shell\";" fullword ascii
    $s17 = "reFilter) - 1471))) == preFilter));" fullword ascii
    $s18 = "mappedTypes = \"W\", module = \"Scr\", isReady = \"Create\", defaultValue = \"Run\", getClientRects = \"b\";" fullword ascii
    $s19 = "er + 3) * (rdisplayswap | 3) * (contexts + 0), ((addEventListener, 195, s) ^ (247, global, 104, nextAll)), ((60 ^ type) / 31), (" ascii
    $s20 = "crossDomain[eventDoc + simple + transports] = ((1 * rdisplayswap) & 0);" fullword ascii

  condition:
    uint16(0) == 0x7974 and
    8 of them
}