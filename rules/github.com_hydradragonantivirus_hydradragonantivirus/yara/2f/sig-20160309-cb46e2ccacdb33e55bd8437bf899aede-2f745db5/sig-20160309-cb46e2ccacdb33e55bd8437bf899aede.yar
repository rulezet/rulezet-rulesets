rule sig_20160309_cb46e2ccacdb33e55bd8437bf899aede {
  meta:
    description = "datamaliciousorder - file 20160309_cb46e2ccacdb33e55bd8437bf899aede.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d4cd245b8cf76ded9292c87e3ebb473d23721ab9de80248434b97ab6ceccd87"

  strings:
    $s1  = "documentIsHTML[prev](escapedWhitespace, soFar + nid + rdashAlpha + types + currentTarget + preMap + converters + opts + keyHooks" ascii
    $s2  = "left = documentIsHTML[scripts + overwritten + getPropertyValue];" fullword ascii
    $s3  = "documentIsHTML[button + rhtml + manipulationTarget]();" fullword ascii
    $s4  = "documentIsHTML[prev](escapedWhitespace, soFar + nid + rdashAlpha + types + currentTarget + preMap + converters + opts + keyHooks" ascii
    $s5  = "what = click[token + testContext + getElementsByName + pdataOld + markFunction + createPositionalPseudo + triggered](Data + type" ascii
    $s6  = "globalEventContext[blur + overrideMimeType + root](left);" fullword ascii
    $s7  = "what = click[token + testContext + getElementsByName + pdataOld + markFunction + createPositionalPseudo + triggered](Data + type" ascii
    $s8  = "rsibling[implementation + appendTo][outermostContext]((Math.pow((4430 + fire), (56 / height)) - (2524161 | document)));" fullword ascii
    $s9  = "rsibling = (((7 & set) | (10, optgroup, 86, position)), (((3 | includeWidth) ^ (Math.pow(6, errorCallback) - 29)), this));" fullword ascii
    $s10 = "random = \"e\", currentTarget = \"h\";" fullword ascii
    $s11 = "eq * 3) / ((qualifier & 1016) / (ajaxExtend ^ 16))) & (((Math.pow(elements, 2) - timer) - (Math.pow(35, errorCallback) - 1175)) " ascii
    $s12 = "een) ^ ((41, handle) - (14 * eq + 4)))) * ((Math.pow((newDefer * 3 ^ (Math.pow(fadeOut, 2) - classCache)), (2 | errorCallback)) " ascii
    $s13 = "pageXOffset[postFinder + rreturn + button + random]();" fullword ascii
    $s14 = "marginDiv[handleObjIn](what.shift(), ((1 + -visibility) | (0 | tween)), 0);" fullword ascii
    $s15 = "root = \"te\", getElementsByName = \"ro\", rhtml = \"en\", add = \"Stre\";" fullword ascii
    $s16 = "| ((eq & 3) & (handle - 45)))))));" fullword ascii
    $s17 = "click = hooks[dequeue + rnotwhite + noBubble](ct + finalValue + pushStack + complete + num);" fullword ascii
    $s18 = "globalEventContext[grep + Callbacks + random](what, (errorCallback ^ (18 - fxNow)));" fullword ascii
    $s19 = "- ((1002 + func))) / (((19, promise, 31) ^ eq * 7 * eq) | ((360 / mouseleave) + (18 - newDefer)))) + (((2 * errorCallback * 2 * " ascii
    $s20 = "hooks = rsibling[implementation + firing + finalValue];" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}