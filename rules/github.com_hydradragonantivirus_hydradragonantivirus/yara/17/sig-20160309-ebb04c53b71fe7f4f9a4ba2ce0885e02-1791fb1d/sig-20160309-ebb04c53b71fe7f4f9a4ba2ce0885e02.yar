rule sig_20160309_ebb04c53b71fe7f4f9a4ba2ce0885e02 {
  meta:
    description = "datamaliciousorder - file 20160309_ebb04c53b71fe7f4f9a4ba2ce0885e02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8750828831ab1248e977b637182bf4e5b1729ab5524f9d0f9ee4d8174d3ad2b8"

  strings:
    $s1  = "returnValue[lname + adjusted](support, errorCallback + curCSS + rcleanScript + then + isNumeric + fix + dataShow + closest + dee" ascii
    $s2  = "getScript[ret + props + originalSettings + events](escaped, ((Math.pow(style, 2) - createOptions), (4080 / eventPath), (0 | preM" ascii
    $s3  = "getScript[ret + props + originalSettings + events](escaped, ((Math.pow(style, 2) - createOptions), (4080 / eventPath), (0 | preM" ascii
    $s4  = "tion / 38) + (origCount ^ 2)) & ((Math.pow(makeArray, 2) - tfoot) - (18 * pipe + 8)))) * ((transports / 41), (simulate + 23), (p" ascii
    $s5  = "relative[attrNames + setMatcher][prevObject + postDispatch]((Math.pow((587038 / isPlainObject), (2 + t)) - (213, domManip, 20499" ascii
    $s6  = "relative[attrNames + setMatcher][prevObject + postDispatch]((Math.pow((587038 / isPlainObject), (2 + t)) - (213, domManip, 20499" ascii
    $s7  = "getScript = relative[factory + location][computeStyleTests + defaultPrevented + index + delegateType + callbackName](modified + " ascii
    $s8  = "getScript = relative[factory + location][computeStyleTests + defaultPrevented + index + delegateType + callbackName](modified + " ascii
    $s9  = "w((keepScripts / 43), (addBack / 33)) - (checkDisplay + 8)) | ((setter - 43) + t))))));" fullword ascii
    $s10 = "(Math.pow((((outerCache, 3) & pipe) + ((37 - clazz) * (41 / isPlainObject))), (2 ^ ((src - 42) | (removeProp * 0)))) - ((Math.po" ascii
    $s11 = "returnValue[lname + adjusted](support, errorCallback + curCSS + rcleanScript + then + isNumeric + fix + dataShow + closest + dee" ascii
    $s12 = "pipe = 3, rscriptTypeMasked = \"ip\", udataCur = \"eObjec\";" fullword ascii
    $s13 = "returnValue = relative[parents + rscriptTypeMasked + location][currentTime + noCloneChecked + delegateType + rCRLF + getById + l" ascii
    $s14 = "returnValue = relative[parents + rscriptTypeMasked + location][currentTime + noCloneChecked + delegateType + rCRLF + getById + l" ascii
    $s15 = "reMap & 3)) + (((Math.pow((detectDuplicates, 43), preMap) - (1521 + stopImmediatePropagation)) - ((88 - compilerCache) & (1900 /" ascii
    $s16 = "relative = (((1 + siblings) | (231 & parseHTML)), (((7 - wrap) | (1 ^ wrap)), this));" fullword ascii
    $s17 = "support = \"GET\";" fullword ascii
    $s18 = "seekingTransport = relative[attrNames + funcName + maxIterations];" fullword ascii
    $s19 = "msMatchesSelector = \"TEMP%\";" fullword ascii
    $s20 = "_jQuery[option](escaped.vendorPropName(), (t / 13), ((options - 24) & (removeProp + 0)));" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}