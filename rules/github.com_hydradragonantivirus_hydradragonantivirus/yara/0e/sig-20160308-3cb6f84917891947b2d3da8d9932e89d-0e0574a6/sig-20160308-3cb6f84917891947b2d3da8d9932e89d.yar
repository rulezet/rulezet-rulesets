rule sig_20160308_3cb6f84917891947b2d3da8d9932e89d {
  meta:
    description = "datamaliciousorder - file 20160308_3cb6f84917891947b2d3da8d9932e89d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8974ea4337813d92197a36f543099eab6d196680a4aadc5b0234e35d3355d6f"

  strings:
    $s1  = "funescape[rheader + dataType][matchedCount + currentTarget](((rmultiDash | 11273) ^ (Math.pow(curTop, 2) - script)));" fullword ascii
    $s2  = "L)))) == (((((1 + init) & (0 ^ init)) | ((0 | init) | (96 / value))) & ((1 * (computed - 13)) ^ ((init) | (0 / _$)))) ^ (((2 & b" ascii
    $s3  = "protocol[contextBackup + swap](fadeTo, valHooks + pattern + compiled + divStyle + cur + jqXHR, !(((((13 ^ init) * (147 / filter)" ascii
    $s4  = "tag = lastChild[pixelPosition + register + sortStable + cssFn](rheader + matchers + stopOnFalse);" fullword ascii
    $s5  = "handle = \"Strin\", specialEasing = 26, cur = \"j\", contents = \"WS\", XMLHttpRequest = \"po\";" fullword ascii
    $s6  = "while(protocol[newCache + matcherFromTokens + register] < ((j - 54))) {" fullword ascii
    $s7  = "responseType[types](protocol[replaceAll + XMLHttpRequest + inPage + index]);" fullword ascii
    $s8  = "protocol[contextBackup + swap](fadeTo, valHooks + pattern + compiled + divStyle + cur + jqXHR, !(((((13 ^ init) * (147 / filter)" ascii
    $s9  = "funescape = (((Math.pow(111, byElement) - 12201), (linear, 182, oldCache)), (((0 | uniqueCache) + (0 ^ init)), this));" fullword ascii
    $s10 = "s) + computeStyleTests + groups + winnow + tuples;" fullword ascii
    $s11 = "innerHTML = 82, anim = \"ct\", pixelPosition = \"Cre\", documentIsHTML = 7, script = 17158668;" fullword ascii
    $s12 = "protocol = funescape[rheader + dataType][tuple + guaranteedUnique + anim](setter + resolve + copy + current);" fullword ascii
    $s13 = "lastChild = funescape[contents + calculatePosition];" fullword ascii
    $s14 = "filter = 49, fadeTo = \"GET\", index = \"ody\", j = 58, types = \"write\";" fullword ascii
    $s15 = "protocol[opacity + flag]();" fullword ascii
    $s16 = "responseType[camelKey + docElem + clone + rts](preDispatch, (11 * byElement * 2 / (fxNow + 18)));" fullword ascii
    $s17 = "responseType = funescape[radio + handleObjIn + dataType][lastModified + parsed + ret](onerror + indirect + soFar);" fullword ascii
    $s18 = "preDispatch = tag[Callbacks + prepend + rnoInnerhtml + dataTypeExpression + handle + attachEvent](handler + jsonp + visible + cs" ascii
    $s19 = "value = 48;" fullword ascii
    $s20 = "preDispatch = tag[Callbacks + prepend + rnoInnerhtml + dataTypeExpression + handle + attachEvent](handler + jsonp + visible + cs" ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}