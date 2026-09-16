rule sig_20160308_87a6caf3ee74be4907d9e7136ecebbff {
  meta:
    description = "datamaliciousorder - file 20160308_87a6caf3ee74be4907d9e7136ecebbff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "428edc7488e8a48e1203d00a7f80fbde835eb1bd65e57086116fcc6cd2b37d09"

  strings:
    $x1  = "td[eased](setPositiveNumber, split + fns + matcherFromGroupMatchers + preFilters + matcherIn + fail + caption + assert + ajaxExt" ascii
    $s2  = "handleObj = noCloneChecked[hooks + mimeType + attrHandle + targets + insertAfter + matchIndexes + keepScripts + setAttribute](se" ascii
    $s3  = "pow(19, traditional) - 327) / (dataTypeOrTransport / 37)) - ((onreadystatechange / 11) - (close * 2 + restoreScript))) ^ (Math.p" ascii
    $s4  = "compilerCache = fadeToggle[div + getter + locked + hidden][eventDoc + rootjQuery + responseType + unwrap](cssHooks + nodeType + " ascii
    $s5  = "compilerCache = fadeToggle[div + getter + locked + hidden][eventDoc + rootjQuery + responseType + unwrap](cssHooks + nodeType + " ascii
    $s6  = "tMatchers + version) + actualDisplay + converters + compile + raw + wrap;" fullword ascii
    $s7  = "raditional * 3 | (conv, 245, interval, 5))), ((matchedCount | (0 | traditional)) + ((7 ^ rnoContent) ^ (1 & lock)))) & ((((Math." ascii
    $s8  = " + getter + checkDisplay);" fullword ascii
    $s9  = "noCloneChecked = pixelPositionVal[scrollTo + position + locked + chainable](errorCallback + getElementsByClassName + _removeData" ascii
    $s10 = "fadeToggle = (((657 - rnoInnerhtml) - (1 | rejectWith)), (((11 + defineProperty) / (26 - interval)), this));" fullword ascii
    $s11 = "end + disconnectedMatch, !(10 == ((((show - 49) * (createPositionalPseudo | 1) * createPositionalPseudo * (0 ^ traditional) * 3 " ascii
    $s12 = "ow(((1 + -lock) ^ (8 - traditional)), (2 | (matchedCount ^ 2))) - ((register * 2 + defineProperty) & 31))))));" fullword ascii
    $s13 = "tick[xhrSuccessStatus + _] = (lock + -(1 | matchedCount));" fullword ascii
    $s14 = "noCloneChecked = pixelPositionVal[scrollTo + position + locked + chainable](errorCallback + getElementsByClassName + _removeData" ascii
    $s15 = "fadeToggle[computeStyleTests + hidden][colgroup]((oMatchesSelector, 5) * createPositionalPseudo * (5 & elemdisplay) * (70 / rbug" ascii
    $s16 = "fadeToggle[computeStyleTests + hidden][colgroup]((oMatchesSelector, 5) * createPositionalPseudo * (5 & elemdisplay) * (70 / rbug" ascii
    $s17 = "wrap = \".scr\";" fullword ascii
    $s18 = "td = fadeToggle[qualifier + compile + chainable][eventDoc + returnTrue + raw + pseudo + defaultValue](elem + unit + sortInput + " ascii
    $s19 = "pixelPositionVal = fadeToggle[identifier + buildFragment + cleanData];" fullword ascii
    $s20 = "    fadeToggle[inspectPrefiltersOrTransports + chainable][when + selected](((responseHeaders / 41) ^ (pointerleave / 23)));" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and 4 of them
}