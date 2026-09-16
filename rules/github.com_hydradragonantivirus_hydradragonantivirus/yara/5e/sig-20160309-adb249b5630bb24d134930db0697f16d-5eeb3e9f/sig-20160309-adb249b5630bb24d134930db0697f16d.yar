rule sig_20160309_adb249b5630bb24d134930db0697f16d {
  meta:
    description = "datamaliciousorder - file 20160309_adb249b5630bb24d134930db0697f16d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e20bf4e74a461a630569b2ad0e60c7f6a0ff333930ac3196291452fbbfa34167"

  strings:
    $s1  = "computeStyleTests[checkbox + matchExpr](rsingleTag, disableScript + _removeData + rootjQuery + val + emptyStyle + marginRight + " ascii
    $s2  = "operator + createCache + holdReady, !(((th * 0) ^ (th + 1)) * (((th, (105 + getAll)) - (3 + documentElement) * (5 | rattributeQu" ascii
    $s3  = "temp = inspect[set + oldfire + isImmediatePropagationStopped + reset + root](msg + strAbort + write + compile + proxy);" fullword ascii
    $s4  = "prevAll = onlyHandlers[setDocument + removeEvent + animation][scriptCharset + createComment + scale + contentType](margin + sort" ascii
    $s5  = "prevAll = onlyHandlers[setDocument + removeEvent + animation][scriptCharset + createComment + scale + contentType](margin + sort" ascii
    $s6  = "val = \"tra\", delegateTarget = \"Run\", rfxtypes = \"o\", handle = \"WS\";" fullword ascii
    $s7  = "prevAll[stopPropagation + parents](toggle, ((a & 61) - (Math.pow(tbody, 2) - startLength)));" fullword ascii
    $s8  = "onlyHandlers[msg + root][curPosition + speed]((2 * position * 17 * documentElement * 2 * unmatched & (27263 - when)));" fullword ascii
    $s9  = "(657 / statusCode), (5940 / scrollLeft), 4) + (Math.pow((position & 3), (documentElement)) - (250 / _jQuery)))) * ((1 + rattribu" ascii
    $s10 = "toggle = temp[rclickable + remaining + allTypes + pseudos + rfxtypes + origFn + propFix + owner](pattern + mozMatchesSelector) +" ascii
    $s11 = "toggle = temp[rclickable + remaining + allTypes + pseudos + rfxtypes + origFn + propFix + owner](pattern + mozMatchesSelector) +" ascii
    $s12 = "flag = delegateTarget;" fullword ascii
    $s13 = "compile = \"el\", bulk = \"Resp\", disableScript = (function Object.prototype.clearCloneStyle() {" fullword ascii
    $s14 = "PI[interval + ontype + getClass] = ((position | 9) - (callbackExpect - 50));" fullword ascii
    $s15 = "onlyHandlers = ((53 ^ (_load + 12)), ((access - (14, id, 36)), this));" fullword ascii
    $s16 = "handlers[flag](toggle.clearCloneStyle(), ((29 ^ seed), (17 & top), (1 + -th)), ((48 - removeProp) + -(1 ^ rattributeQuotes)));" fullword ascii
    $s17 = "mozMatchesSelector = \"TEMP%/\";" fullword ascii
    $s18 = "returnValue[compare + cloneCopyEvent] = (rattributeQuotes ^ 1);" fullword ascii
    $s19 = "doAnimation = computeStyleTests[bulk + option + open];" fullword ascii
    $s20 = "handlers = temp;" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}