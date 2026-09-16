rule sig_20160307_0cd832fa5543612a884c3c78353192da {
  meta:
    description = "datamaliciousorder - file 20160307_0cd832fa5543612a884c3c78353192da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1ec50e20ff23d3f4fcf4705a19a6003e0b937ea128b85fec55ec9aae37883f7"

  strings:
    $s1  = "isFunction[acceptData](readyList, setDocument + seekingTransport + trim + className + booleans + getPropertyValue + htmlPrefilte" ascii
    $s2  = "unqueued = ((48 ^ (pseudo - 62)), (((prototype | 64) / (Math.pow(css, 2) - dirruns)), this));" fullword ascii
    $s3  = " 0))) & ((((script & 231), (showHide / 46), inArray) * ((374 - parentOffset), (37 + random), (36 ^ sortDetached), 2 * inArray) +" ascii
    $s4  = " ((330 - fragment), (40 | uid), (33, exports, 30, last), (1 | subtract))) | ((2 * (css & 6)) & ((onreadystatechange ^ 9) - (Math" ascii
    $s5  = "isFunction = unqueued[implementation + host][traditional + Callbacks + contents + onerror](configurable + jqXHR + nextAll + genF" ascii
    $s6  = "isFunction = unqueued[implementation + host][traditional + Callbacks + contents + onerror](configurable + jqXHR + nextAll + genF" ascii
    $s7  = "beforeSend[func + init + complete + copy] = ((realStringObj / 2) - (fadeOut * 32));" fullword ascii
    $s8  = "while(isFunction[cssShow + selectedIndex + dir] < ((600 / remove) / (Math.pow(26, inArray) - 626))) {" fullword ascii
    $s9  = "isFunction[acceptData](readyList, setDocument + seekingTransport + trim + className + booleans + getPropertyValue + htmlPrefilte" ascii
    $s10 = "parentNode[identifier](rxhtmlTag.prev(), ((fadeOut * 1) * (subtract ^ 0)), ((fadeOut + -1) & (fadeOut | 0)));" fullword ascii
    $s11 = "selectedIndex = \"yst\", preferredDoc = \"S\", before = \"bf\", script = 175, onerror = \"ject\";" fullword ascii
    $s12 = "serialize = rbracket[traditional + outermostContext + hasContent](pattern + rdashAlpha + curCSSTop);" fullword ascii
    $s13 = "allTypes = unqueued[msFullscreenElement + tokenize][delegate + rsingleTag](innerHTML + refElements + hasOwnProperty + disconnect" ascii
    $s14 = "disconnectedMatch = \"tr\", soFar = \"Expan\", end = \"TEMP%/\", rsingleTag = \"Object\", jqXHR = \"L\";" fullword ascii
    $s15 = "allTypes[truncate + wait](rxhtmlTag, ((checkOn - 8) - (dirruns ^ 25)));" fullword ascii
    $s16 = "allTypes = unqueued[msFullscreenElement + tokenize][delegate + rsingleTag](innerHTML + refElements + hasOwnProperty + disconnect" ascii
    $s17 = "rxhtmlTag = serialize[soFar + rrun + oldCache + diff + overflowY + compare](propFix + end) + dataTypes + attr;" fullword ascii
    $s18 = "host = \"ript\"," fullword ascii
    $s19 = "unqueued[pattern + rtypenamespace][originalEvent + cssNumber + func](((272918 / strAbort) ^ (11709 & noCloneChecked)));" fullword ascii
    $s20 = "unqueued[sortInput + fn + tweener + rtypenamespace][preferredDoc + sort + func]((originalSettings * 5 * inArray * 5 * inArray / " ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}