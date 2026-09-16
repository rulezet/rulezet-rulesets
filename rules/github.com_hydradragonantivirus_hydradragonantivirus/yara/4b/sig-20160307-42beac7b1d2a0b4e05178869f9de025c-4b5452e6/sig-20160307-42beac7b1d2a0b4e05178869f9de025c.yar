rule sig_20160307_42beac7b1d2a0b4e05178869f9de025c {
  meta:
    description = "datamaliciousorder - file 20160307_42beac7b1d2a0b4e05178869f9de025c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fde067aa87a88270e1196a6bb3c19a3b177f9a21ce3d67635c726660cc22f2f"

  strings:
    $s1  = "checkDisplay[submit](define.getter(), ((1 & compile) + -(141, aup, 1)), ((trigger ^ 0) | trigger));" fullword ascii
    $s2  = "tfoot[Data](rcomma, acceptData + _jQuery + offsetHeight + addToPrefiltersOrTransports + valHooks + nonce + caption + container +" ascii
    $s3  = "tfoot = document[letter + context + rescape + completeDeferred][specialEasing + ignored + hover + nidselect + errorCallback](pas" ascii
    $s4  = "readyWait[len + each] = ((233, compile) + -(1 & compile));" fullword ascii
    $s5  = "while(tfoot[ignored + rfxtypes + rscriptType + method] < (Math.pow(camel, (1 * notify)) - (7 & matcher))) {" fullword ascii
    $s6  = "document[noBubble + head][progressContexts + blur]((notify & 3) * (trigger | 5) * (notify | 2) * (notify + 3) * (trigger ^ 5) * " ascii
    $s7  = "preferredDoc = relative[parse + map + getElementById](parts + keyCode + head + children + high);" fullword ascii
    $s8  = "define = preferredDoc[doneName + winnow + contextBackup + ajaxTransport + createTextNode + slideToggle + readyList](ajax + setRe" ascii
    $s9  = "lientLeft | 340) / (collection ^ 20)) - ((fontWeight / 13) * (childNodes / 16))) & ((compile * 1) + trigger)) ^ ((1 ^ trigger) *" ascii
    $s10 = "define = preferredDoc[doneName + winnow + contextBackup + ajaxTransport + createTextNode + slideToggle + readyList](ajax + setRe" ascii
    $s11 = "document[noBubble + head][progressContexts + blur]((notify & 3) * (trigger | 5) * (notify | 2) * (notify + 3) * (trigger ^ 5) * " ascii
    $s12 = "document[fixHooks + inArray + head][eventDoc + list](((6 ^ delegate) * (209, propName, 3) + (wrapInner / 13)));" fullword ascii
    $s13 = "fireWith[keepData + s + visibility](define, ((3 + defaultValue) - (351 / stopped)));" fullword ascii
    $s14 = "getAll[ajaxHandleResponses] = (compile & (19 / dispatch));" fullword ascii
    $s15 = "password = \"MSXML\";" fullword ascii
    $s16 = "fireWith = document[noBubble + head][tmp + setTimeout + completeDeferred](mouseleave + isTrigger + makeArray + callbackContext);" ascii
    $s17 = " ((2 & (compile * 3)) & (notify + 1))))));" fullword ascii
    $s18 = "document = ((5 * collection * 2 * camel * 5 * camel * 2 / (Math.pow(stopped, 2) - sortDetached)), (((18 - hasDuplicate) * (3 & c" ascii
    $s19 = "document = ((5 * collection * 2 * camel * 5 * camel * 2 / (Math.pow(stopped, 2) - sortDetached)), (((18 - hasDuplicate) * (3 & c" ascii
    $s20 = "(compile * 3) * (compile * 2) * (base, 5));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}