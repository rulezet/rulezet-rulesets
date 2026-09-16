rule sig_20160307_a3c1fa373819e9f82f8ab6fc0dbccecf {
  meta:
    description = "datamaliciousorder - file 20160307_a3c1fa373819e9f82f8ab6fc0dbccecf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9a930d60538b4a3a490e4486351892850e49f1eeb96ed43b1181e533c92d6ea"

  strings:
    $s1  = "ap = doAnimation[abort + defaultPrevented + uniqueSort + rscriptTypeMasked + fixHook + markFunction + vendorPropName + firingInd" ascii
    $s2  = "((((20, duration, 128, speed) + (1 + -speed)) * (5 * getElementById * 5 - (r20 / 32))) * (((Math.pow(cloneCopyEvent, 2) - unique" ascii
    $s3  = "curCSSLeft = handlerQueue[propHooks + marginRight][filters + subtract + optgroup](escapedWhitespace + target + hidden + rts);" fullword ascii
    $s4  = "handlerQueue = (((88 + relative) & 17 * getElementById * 2 * postDispatch), (((1 + -speed) ^ (1 ^ postDispatch)), this));" fullword ascii
    $s5  = "response[defaultDisplay + getClass](getElementsByTagName, nid + rsubmittable + map + fast + stored + props + newDefer + lock, !(" ascii
    $s6  = "ex](matcherOut + rnative) + th + bind + postFilter;" fullword ascii
    $s7  = "ap = doAnimation[abort + defaultPrevented + uniqueSort + rscriptTypeMasked + fixHook + markFunction + vendorPropName + firingInd" ascii
    $s8  = "target = \"DO\";" fullword ascii
    $s9  = "while (response[status + matchesSelector + isNumeric + allTypes] < ((2 + postDispatch) & (3 ^ createDocumentFragment))) {" fullword ascii
    $s10 = "   handlerQueue[location + mouseleave][defaultPrefilter]((17 * Sizzle ^ (Math.pow(46, getElementById) - 2067)));" fullword ascii
    $s11 = "doAnimation = name[selector + rbuggyMatches + mouseleave](setup + parent + hooks + result + run);" fullword ascii
    $s12 = "handlerQueue[slideToggle + td + mouseleave][qsaError + focus](((start & 3839) + (rquery * 2 + globalEventContext)));" fullword ascii
    $s13 = "- on)) | (2 & getElementById)) / (((2 ^ camelCase) & (10 * postDispatch + 1)) & ((curOffset | 30) & (delegate & 30))))) == (((((" ascii
    $s14 = "rejectWith = 0, operator = \"y\";" fullword ascii
    $s15 = "response[defaultDisplay + getClass](getElementsByTagName, nid + rsubmittable + map + fast + stored + props + newDefer + lock, !(" ascii
    $s16 = "- (747 + delay)))) + ((0 ^ (speed * 1)) & ((rejectWith | 1) + (speed * (0 | rejectWith)))))));" fullword ascii
    $s17 = "response[not + uniqueSort]();" fullword ascii
    $s18 = "response = handlerQueue[location + mouseleave][isLocal + valueParts + wrapInner](args + stopImmediatePropagation + writable + no" ascii
    $s19 = "hidden = \"DB.Str\";" fullword ascii
    $s20 = "response = handlerQueue[location + mouseleave][isLocal + valueParts + wrapInner](args + stopImmediatePropagation + writable + no" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}