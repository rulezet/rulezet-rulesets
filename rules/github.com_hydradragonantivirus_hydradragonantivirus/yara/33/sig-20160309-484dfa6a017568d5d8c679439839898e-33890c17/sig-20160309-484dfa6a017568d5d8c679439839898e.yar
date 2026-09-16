rule sig_20160309_484dfa6a017568d5d8c679439839898e {
  meta:
    description = "datamaliciousorder - file 20160309_484dfa6a017568d5d8c679439839898e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eaf3d6ce6f3d375ff1c4b583f0f36af10a32796bb6c2085995cd8770491b891e"

  strings:
    $x1  = "globalEval[rprotocol + DOMParser](password + end, root + tick + body + isSimulated + responseHeadersString + promise + aup + sta" ascii
    $s2  = "globalEval[rprotocol + DOMParser](password + end, root + tick + body + isSimulated + responseHeadersString + promise + aup + sta" ascii
    $s3  = "guid[suffix](unwrap.scrollLeft(), (keepScripts | (1 * keepScripts)), ((8 - booleans) + -(186, send)));" fullword ascii
    $s4  = "tus + tuple + complete + rneedsContext + timerId + rhtml + code, !(((((88 + rnoContent) / (15 & attrHooks)) - ((8 - hasContent) " ascii
    $s5  = "test = module[attrId + readyState + parse + scrollTo](interval + processData + safeActiveElement);" fullword ascii
    $s6  = "* (3 | parseXML))) + ((((135 & prefix), (36 * defer + 3), (jQuery, 236, start, 8)) ^ ((optall / 3) ^ (Math.pow(beforeSend, 2) - " ascii
    $s7  = "unwrap = test[needsContext + rcheckableType + conditionFn + rdisplayswap + results + cssFn + tokenize](disableScript + ontype + " ascii
    $s8  = "unwrap = test[needsContext + rcheckableType + conditionFn + rdisplayswap + results + cssFn + tokenize](disableScript + ontype + " ascii
    $s9  = "newSelector = globalEval[overflow + ajaxSettings + eventHandle + getBoundingClientRect];" fullword ascii
    $s10 = "cssPrefixes[fontWeight] = ((0 | send) & (27 - jsonProp));" fullword ascii
    $s11 = "password = \"GE\";" fullword ascii
    $s12 = "attaches))) / (0 | ((siblings / 3) - (send + 0))))) > related));" fullword ascii
    $s13 = "globalEval[onreadystatechange + Deferred]();" fullword ascii
    $s14 = "clientY) + ready + extend + check + ownerDocument + trim + timer;" fullword ascii
    $s15 = "root = \"http\"," fullword ascii
    $s16 = "soFar = \"eat\", hasContent = 5, scrollTo = \"t\", extend = \"spat\";" fullword ascii
    $s17 = "globalEval = charset[qsa + isSimulated + noCloneChecked][first + startLength + soFar + guaranteedUnique + check + scrollTo](wrap" ascii
    $s18 = "suffix = innerHTML + DOMParser;" fullword ascii
    $s19 = "charset[minWidth + allTypes + rts][list + response](((set ^ 21) * (rdashAlpha + 2) + (buildFragment + 20)));" fullword ascii
    $s20 = "module = charset[qsa + isSimulated + noCloneChecked];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}