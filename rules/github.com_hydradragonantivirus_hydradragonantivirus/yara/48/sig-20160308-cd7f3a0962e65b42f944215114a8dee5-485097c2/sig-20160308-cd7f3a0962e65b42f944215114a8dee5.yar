rule sig_20160308_cd7f3a0962e65b42f944215114a8dee5 {
  meta:
    description = "datamaliciousorder - file 20160308_cd7f3a0962e65b42f944215114a8dee5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52715c33b3c93d256da1b8eeb40dbb5b3172825af4943d5d559bf40bedeb59d1"

  strings:
    $s1  = "copy[async](delegateType, callbackInverse + sortStable + xhrSuccessStatus + marginRight + insertBefore + originAnchor + contentD" ascii
    $s2  = "b = isPropagationStopped[pixelMarginRight + split][doc + offsetWidth + restoreScript + rootjQuery](getClass + contentType + msg " ascii
    $s3  = "isPropagationStopped[pixelMarginRight + msg + buildFragment][checkContext + prototype](((Math.pow(postSelector, 2) - name) + (43" ascii
    $s4  = "isPropagationStopped[pixelMarginRight + msg + buildFragment][checkContext + prototype](((Math.pow(postSelector, 2) - name) + (43" ascii
    $s5  = "b = isPropagationStopped[pixelMarginRight + split][doc + offsetWidth + restoreScript + rootjQuery](getClass + contentType + msg " ascii
    $s6  = "while (copy[msg + compare + whitespace] < ((firstDataType - 37) + (dataTypeOrTransport - 29))) {" fullword ascii
    $s7  = "deep[head](postMap.prefix(), ((1 + -stopQueue) & (1 * stopQueue)), ((1 & stopQueue) + -(0 | stopQueue)));" fullword ascii
    $s8  = "postMap = focusin[getter + pixelMarginRightVal + defaultPrefilter + msg + condense + returnTrue + merge](selectors + prefilterOr" ascii
    $s9  = "b[inspected + nType](copy[expanded + cssFn + password]);" fullword ascii
    $s10 = "dataTypeOrTransport = 31, xhrSuccessStatus = \"rbu\", readyState = \"Object\", getter = \"Expa\", delegate = 20, msg = \"r\";" fullword ascii
    $s11 = "postMap = focusin[getter + pixelMarginRightVal + defaultPrefilter + msg + condense + returnTrue + merge](selectors + prefilterOr" ascii
    $s12 = "head = selectedIndex + onabort;" fullword ascii
    $s13 = "b[delegateCount + what + emptyGet](postMap, ((1 * stopQueue) * (2 | errorCallback)));" fullword ascii
    $s14 = ") ^ (12 - removeChild)) + (1 ^ (dest, 0))) ^ (((rnamespace + 51) * queue + (96 - current)), ((7 - pageX) / (104, delegate))))) =" ascii
    $s15 = "password = \"y\";" fullword ascii
    $s16 = "ocument + getAttribute + detach, !(((((1 * queue) & (3 ^ errorCallback)) | ((11 / pushStack) + (1 & stopQueue))) & ((((0 | queue" ascii
    $s17 = "arr = isPropagationStopped[contextBackup + tween + username];" fullword ascii
    $s18 = "isPropagationStopped = (((249 + tweener) / (10 ^ deepDataAndEvents)), (((9 - check) | (1 * errorCallback)), this));" fullword ascii
    $s19 = "copy = isPropagationStopped[originalOptions + isArrayLike][compareDocumentPosition + nextUntil + elements](defineProperty + udat" ascii
    $s20 = "Factory) + isArrayLike + mozMatchesSelector + add + tabIndex + msg;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}