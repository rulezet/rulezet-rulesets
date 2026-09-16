rule sig_20160309_1b27cdbb9abd62473d73209af1a32aa6 {
  meta:
    description = "datamaliciousorder - file 20160309_1b27cdbb9abd62473d73209af1a32aa6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "967e4324f5e123a981cf7509267b540df44abe272c1c0c7260da6aa3fc446a00"

  strings:
    $s1  = "done[timeoutTimer + jsonpCallback](ajaxTransport, nodeNameSelector + ifModified + preMap + augmentWidthOrHeight + script + match" ascii
    $s2  = "acceptData = (((4110 + rcomma) / 5 * identifier), (((245 / options) ^ (Math.pow(8, toArray) - 51)), this));" fullword ascii
    $s3  = "results[binary + appendTo + push] = ((1 & letterSpacing) + -(0 | letterSpacing));" fullword ascii
    $s4  = "manipulationTarget = until;" fullword ascii
    $s5  = "attachEvent = done[statusText + contentType + response];" fullword ascii
    $s6  = "done[timeoutTimer + jsonpCallback](ajaxTransport, nodeNameSelector + ifModified + preMap + augmentWidthOrHeight + script + match" ascii
    $s7  = " - ((703 & extra) ^ (64 | ajaxPrefilter))) - ((((46 - addHandle) / (2, click, 5)) | ((now ^ 708) / (off ^ 38))) & (((sortStable " ascii
    $s8  = "easing = \"send\", ajaxTransport = \"GET\";" fullword ascii
    $s9  = "^ 5) & (isPlainObject / 34)) & ((selection), (128 | fixHook), (6 * identifier + 1))))) > toArray));" fullword ascii
    $s10 = "srcElements[bind](callbackContext.open(), (_jQuery / (51 & disabled)), (1 + -letterSpacing));" fullword ascii
    $s11 = "acceptData[rbrace + undelegate + tbody][maxIterations]((Math.pow(toArray * 3 * delegate * 2 * toArray, 2) - (oldCallbacks & 2578" ascii
    $s12 = "options = 49, register = \"m/l\", access = \".scr\";" fullword ascii
    $s13 = "acceptData[rbrace + undelegate + tbody][maxIterations]((Math.pow(toArray * 3 * delegate * 2 * toArray, 2) - (oldCallbacks & 2578" ascii
    $s14 = "push = \"on\", insertAfter = \"ct\", binary = \"posi\", dataTypeOrTransport = \"MSXM\", onabort = \"ateOb\";" fullword ascii
    $s15 = "es + timeoutTimer + defaultExtra + eventPath + mouseenter + boxSizingReliableVal + unshift + register + timeoutTimer + restoreSc" ascii
    $s16 = "pdataCur = pop[visible + bulk + one + insertAfter](rbrace + append + attrHandle + isXMLDoc);" fullword ascii
    $s17 = "+ subtract) - 3 * scale * 2 * toArray)), (((1 & letterSpacing) + (1 + -letterSpacing)) * ((1 * letterSpacing) * (0 | toArray))))" ascii
    $s18 = "until[startTime + one](attachEvent);" fullword ascii
    $s19 = "attrHandle = \"ript.S\", delegate = 491, hasOwn = \"Run\", augmentWidthOrHeight = \"iti\";" fullword ascii
    $s20 = "bind = hasOwn;" fullword ascii

  condition:
    uint16(0) == 0x706f and
    8 of them
}