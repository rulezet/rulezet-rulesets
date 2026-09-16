rule sig_20160309_8313ffb867cd3e977fac43f521e104bd {
  meta:
    description = "datamaliciousorder - file 20160309_8313ffb867cd3e977fac43f521e104bd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf9188bb58310a0431606dc71f664056962ff170319055f386f302507b860386"

  strings:
    $s1  = " | 0)))) * (((getWidthOrHeight ^ 9) * getWidthOrHeight * (17 - temp) - ((117 & removeData) - (64 | tick)))))));" fullword ascii
    $s2  = "fixHook[elements](getElementsByName.rsingleTag(), ((qualifier + -1) ^ optgroup), ((48 / host) + -(1 & qualifier)));" fullword ascii
    $s3  = "elemLang[firingIndex + rCRLF](onload, prependTo + removeClass + timeout + cur + promise + el + globalEval + compilerCache + marg" ascii
    $s4  = " - 23) - (hold - 40)) * (getWidthOrHeight * 3 - (optgroup | 5))) ^ (((optgroup | 1) * (one / 34)) * ((specified, 0) & (qualifier" ascii
    $s5  = "clearQueue = ((Math.pow((16 + caption), (80 / key)) - (852 + nativeStatusText)), (((38 + sibling) - (19 + addCombinator)), this)" ascii
    $s6  = "clearQueue = ((Math.pow((16 + caption), (80 / key)) - (852 + nativeStatusText)), (((38 + sibling) - (19 + addCombinator)), this)" ascii
    $s7  = "headers = \"pe\", one = 34, document = \"MSXML\", temp = 15;" fullword ascii
    $s8  = "elemLang = clearQueue[offsetHeight + classCache][rfocusMorph + requestHeaders + removeAttr + find](document + unique + hookFn + " ascii
    $s9  = "clearQueue[$ + actualDisplay][height]((PI & 7) * (getWidthOrHeight ^ 1) * getWidthOrHeight * (5 | qualifier) * 2 * (qualifier | " ascii
    $s10 = "getElementsByName = view[letterSpacing + etag + pseudo + excess + rquery + abort + nodeNameSelector](unmatched + cors) + overflo" ascii
    $s11 = "body[createHTMLDocument + sortInput + flag](getElementsByName, 2);" fullword ascii
    $s12 = "simple[setMatched + headers] = (0 | qualifier);" fullword ascii
    $s13 = "clearQueue[$ + actualDisplay][height]((PI & 7) * (getWidthOrHeight ^ 1) * getWidthOrHeight * (5 | qualifier) * 2 * (qualifier | " ascii
    $s14 = "inDiv + stopImmediatePropagation + tweeners + file + postFinder + getter + rinputs + namespace + ajaxPrefilter, !(7 == (((((Data" ascii
    $s15 = "getElementsByName = view[letterSpacing + etag + pseudo + excess + rquery + abort + nodeNameSelector](unmatched + cors) + overflo" ascii
    $s16 = "prev = \"pt.She\", global = \"ite\", letterSpacing = \"Expa\", string = \"WScri\", sibling = 4, removeEventListener = \"am\";" fullword ascii
    $s17 = "body = clearQueue[$ + actualDisplay][rattributeQuotes + rclickable + sort + unit + compile](offsetParent + escaped + isHidden + " ascii
    $s18 = "key = 40, addCombinator = 20, promise = \"edici\", find = \"ject\";" fullword ascii
    $s19 = "elemLang = clearQueue[offsetHeight + classCache][rfocusMorph + requestHeaders + removeAttr + find](document + unique + hookFn + " ascii
    $s20 = "getter = \"gf\", actualDisplay = \"t\", file = \"s/7\", self = \"eObjec\";" fullword ascii

  condition:
    uint16(0) == 0x6144 and
    8 of them
}