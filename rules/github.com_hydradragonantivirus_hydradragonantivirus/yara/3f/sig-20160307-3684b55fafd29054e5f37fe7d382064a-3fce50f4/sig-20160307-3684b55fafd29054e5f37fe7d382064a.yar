rule sig_20160307_3684b55fafd29054e5f37fe7d382064a {
  meta:
    description = "datamaliciousorder - file 20160307_3684b55fafd29054e5f37fe7d382064a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af6807181193250cdb3bcda15174103bd1b36510f0e96055b1eddd6a8340872c"

  strings:
    $s1  = "Success))) - ((25 ^ setOffset) - (5 * exports + 1))), (((protocol & 7) * (scrollTop + 1) * (version * 5) / (completed, 169, send" ascii
    $s2  = "notify[v](animation + nonce, preexisting + err + hover + propHooks + querySelectorAll + key + removeClass, !(10 < (Math.pow(((sc" ascii
    $s3  = ", 7) * (version | 4)) & (scrollTop + 0))) - (Math.pow((((conv2, 213, version) + (Math.pow(9, scrollTop) - 69)) * (Math.pow((expo" ascii
    $s4  = "rts ^ 12), (transport - 7)) - (constructor * 7)) + (setOffset * (1 * scrollTop) + (0 | version))), ((2 + (version | 1)) & ((tr /" ascii
    $s5  = "unqueued = (((79 & adown) - (16 ^ postDispatch)), (((308 / rcheckableType) ^ (110, updateFunc)), this));" fullword ascii
    $s6  = "while(notify[contextBackup + rhash + testContext + active + locked] < ((1 * scrollTop) * (59, overrideMimeType, 2))) {" fullword ascii
    $s7  = "getComputedStyle = clearQueue[isXML + show + pixelPosition + origCount + pos + siblings + collection + outermostContext](cos + o" ascii
    $s8  = "getComputedStyle = clearQueue[isXML + show + pixelPosition + origCount + pos + siblings + collection + outermostContext](cos + o" ascii
    $s9  = " 2) - (origFn | 5)))) - (((showHide ^ 101450) | (Math.pow(curValue, 2) - speed)) / ((4 | serialize) * (20 / constructor) + (1 * " ascii
    $s10 = "notify = unqueued[excess + count][replaceAll + rheaders + returnTrue](requestHeaders + cleanData + refElements + rpseudo);" fullword ascii
    $s11 = "clearQueue = tick[triggered + operator + defaultExtra + rts + sortDetached](condense + timerId + fadeOut);" fullword ascii
    $s12 = "postFinder = \"m\", version = 1, isSuccess = 55;" fullword ascii
    $s13 = "iNoClone = unqueued[propName + sortDetached][blur + active + xhrFields + funescape](className + attrId + truncate + height + pos" ascii
    $s14 = "    iNoClone[converters + nonce + genFx + rcomma](getComputedStyle, ((44, what, 59, updateFunc) | (2 | updateFunc)));" fullword ascii
    $s15 = "    doc[byElement] = ((48 - compare) | (10 / constructor));" fullword ascii
    $s16 = "notify[v](animation + nonce, preexisting + err + hover + propHooks + querySelectorAll + key + removeClass, !(10 < (Math.pow(((sc" ascii
    $s17 = "noCloneChecked = \"p\", speed = 565483332731, pos = \"viron\", operator = \"eat\";" fullword ascii
    $s18 = "defaultExtra = \"eO\", matcherOut = \"seBody\", fadeOut = \"ell\", condense = \"WScr\", rheaders = \"Obje\";" fullword ascii
    $s19 = "notify[progress + statusCode]();" fullword ascii
    $s20 = "tick = unqueued[condense + elem];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}