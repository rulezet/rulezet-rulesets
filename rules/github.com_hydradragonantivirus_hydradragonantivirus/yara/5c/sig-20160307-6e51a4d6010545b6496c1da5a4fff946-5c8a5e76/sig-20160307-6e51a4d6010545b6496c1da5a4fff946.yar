rule sig_20160307_6e51a4d6010545b6496c1da5a4fff946 {
  meta:
    description = "datamaliciousorder - file 20160307_6e51a4d6010545b6496c1da5a4fff946.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "281f0aea6e6a5d373f6adcc73e4c225bf2952d257df533567d7e870105f92f18"

  strings:
    $s1  = "ontype[clazz](finalValue + jsonProp, prepend + event + seekingTransport + find + box + ajaxSetup + rootjQuery + stored, !(fireGl" ascii
    $s2  = "contents = \"%TEMP%\";" fullword ascii
    $s3  = "hasOwnProperty[slow + getComputedStyle + high] = ((fn | 0) ^ fn);" fullword ascii
    $s4  = "attrHandle[converters + hold + getAllResponseHeaders][parents + removeEvent + firstElementChild]((udataCur & 2) * (inspectPrefil" ascii
    $s5  = " - ((Math.pow(what, 2) - firstDataType) * (2 & udataCur) * (2 + fn) | ((21 + doScroll) - (144 - values)))))));" fullword ascii
    $s6  = "documentIsHTML = cssExpand[rkeyEvent + capName + cur](last + resolveContexts + locked + checkClone + rsubmitterTypes + bindType)" ascii
    $s7  = "ue | 1) * (doAnimation / 6)), ((fn | (0 ^ fn)) | ((1 + -nodeValue) | (1 * inspectPrefiltersOrTransports)))) - (((243040 / margin" ascii
    $s8  = "attrHandle = ((Math.pow((111 ^ hooks), 2) - (origType ^ 24579)), ((nodeValue * 2) * (modified - 8), this));" fullword ascii
    $s9  = "documentIsHTML = cssExpand[rkeyEvent + capName + cur](last + resolveContexts + locked + checkClone + rsubmitterTypes + bindType)" ascii
    $s10 = "(fns - (312 / modified)) & ((206 + marginLeft)))), (Math.pow((1 * (udataCur * 7 * style, (18 * what + 16), (ajaxExtend - 95), in" ascii
    $s11 = "set = documentIsHTML[tabIndex + escaped + wait + condense + handler + currentTime + func](contents + ready) + th + outermostCont" ascii
    $s12 = "set = documentIsHTML[tabIndex + escaped + wait + condense + handler + currentTime + func](contents + ready) + th + outermostCont" ascii
    $s13 = "ontype[clazz](finalValue + jsonProp, prepend + event + seekingTransport + find + box + ajaxSetup + rootjQuery + stored, !(fireGl" ascii
    $s14 = "cssExpand = attrHandle[file + after + hasScripts];" fullword ascii
    $s15 = "attrHandle[file + parents + defaultPrevented + hold + getAllResponseHeaders][callbackInverse + hasOwn]((8 * (matcher - 2) + (dat" ascii
    $s16 = "attrHandle[converters + hold + getAllResponseHeaders][parents + removeEvent + firstElementChild]((udataCur & 2) * (inspectPrefil" ascii
    $s17 = "attrHandle[file + parents + defaultPrevented + hold + getAllResponseHeaders][callbackInverse + hasOwn]((8 * (matcher - 2) + (dat" ascii
    $s18 = "aup[isImmediatePropagationStopped + inspect] = ((nodeValue ^ 0) ^ (nodeValue + -1));" fullword ascii
    $s19 = "style = 7, rreturn = \"d\", getComputedStyle = (function String.prototype.fnOut() {" fullword ascii
    $s20 = "Left) ^ (274 + guaranteedUnique)) | ((220, compareDocumentPosition, 113, duplicates), (169, textContent), (163 | wrapInner), (70" ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}