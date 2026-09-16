rule sig_20160309_039651ee08a7d985a7a0e56e158aa38d {
  meta:
    description = "datamaliciousorder - file 20160309_039651ee08a7d985a7a0e56e158aa38d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc5071a3ba3ae4e11675fe83818fd86ee5cb8b1222c615ce5eab051c0eef79cf"

  strings:
    $s1  = "completeDeferred = slideToggle[styles + preventDefault + newDefer + n + delegateTarget](createHTMLDocument + dirrunsUnique + del" ascii
    $s2  = "lname = completeDeferred[_load + submit + cssFn + origFn + pattern + image + preDispatch + preventDefault + cssShow + promise](c" ascii
    $s3  = "heckNonElements + parseHTML) + processData + reverse + responseFields;" fullword ascii
    $s4  = "* 2))) * ((currentValue * 3 * currentValue * 2, (inspect & 126), (Math.pow(ajaxSetup, 2) - scrollLeft)) | ((2 * currentValue + 1" ascii
    $s5  = "egateTarget + dataFilter + defer);" fullword ascii
    $s6  = "Deferred = inArray[clearTimeout + delegateTarget][valueParts + newDefer + n + delegateTarget](charCode + linear + onabort);" fullword ascii
    $s7  = "curOffset[reliableMarginLeftVal](removeData + special, offsetParent + rheaders + _data + structure + all + base + responseHeader" ascii
    $s8  = "curOffset[reliableMarginLeftVal](removeData + special, offsetParent + rheaders + _data + structure + all + base + responseHeader" ascii
    $s9  = "Deferred[nodes + dataShow + get + cacheLength](lname, ((750 / matchers) - (32 | push_native)));" fullword ascii
    $s10 = ") & (deep / 46)))) | ((((dest - 39) | (p, 5)) & ((ret - 18) | currentValue)) + ((0 ^ div) | ((33 + currentValue) - (55 & matched" ascii
    $s11 = "inArray[boxSizingReliableVal + sortInput][dataPriv](((328671 - check) / (4 * p + 1)));" fullword ascii
    $s12 = "inArray = (((42 ^ documentElement) * (20 - matchers)), ((5 + (speed, 7, div)), this));" fullword ascii
    $s13 = "curOffset = inArray[eventHandle + slideUp][complete + overflow + href](genFx + needsContext + startLength + booleans);" fullword ascii
    $s14 = "lname = completeDeferred[_load + submit + cssFn + origFn + pattern + image + preDispatch + preventDefault + cssShow + promise](c" ascii
    $s15 = "valueParts = \"Cr\", preventDefault = \"r\", preDispatch = \"mentSt\", end = \"ns\", get = \"oFil\", removeData = \"G\";" fullword ascii
    $s16 = "push_native = 16, ret = 22, deep = (function Object.prototype.getElementsByName() {" fullword ascii
    $s17 = "pdataCur = curOffset[ajaxPrefilter + rfocusMorph + end + radio];" fullword ascii
    $s18 = "slideToggle = inArray[createHTMLDocument + traditional + sortInput];" fullword ascii
    $s19 = "document[send + notifyWith] = ((tag & 38), div);" fullword ascii
    $s20 = "keyHooks[detach + cacheLength] = (Expr | 0);" fullword ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}