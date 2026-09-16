rule sig_20160308_72cb9c7ddde242c3dd6d1dd779f849c0 {
  meta:
    description = "datamaliciousorder - file 20160308_72cb9c7ddde242c3dd6d1dd779f849c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cd7ecc31c1dfce443f812dfdce3a213e6765c70640e1db7ac827474458eae35"

  strings:
    $s1  = "tokenCache = keyCode[getById + ajaxTransport + getScript + stopped](compiled + parsed + offset + adjusted);" fullword ascii
    $s2  = "fnOut = tokenCache[bindType + close + computeStyleTests + preMap + rjsonp + stateVal + rwhitespace + optSelected + html + get](c" ascii
    $s3  = "urValue + firstDataType + finalDataType) + cos + getClientRects + invert + outermostContext + addToPrefiltersOrTransports;" fullword ascii
    $s4  = "fnOut = tokenCache[bindType + close + computeStyleTests + preMap + rjsonp + stateVal + rwhitespace + optSelected + html + get](c" ascii
    $s5  = "compile = \"ttp:\", parsed = \"ipt\", handlers = \"65gh5\", isSimulated = \"am\";" fullword ascii
    $s6  = "addToPrefiltersOrTransports = \"cr\", charset = \"GET\", stopped = \"t\";" fullword ascii
    $s7  = "swap[checkDisplay + getElementsByClassName + holdReady](fnOut, ((traditional | 0) + (curTop / 47)));" fullword ascii
    $s8  = "_jQuery = (((658 & size) / (580 / sel)), (((226, pattern, 169, after) + -1), this));" fullword ascii
    $s9  = "e + handlers, !((((((after * 0)) | ((curTop))) & (((1 ^ curTop) + -(1 + curTop)) | (0 | after))) | ((1 & after) | ((3 & strAbort" ascii
    $s10 = "swap = _jQuery[raw + replaceAll][getById + ajaxTransport + stateString](rCRLF + booleans + msMatchesSelector + isSimulated);" fullword ascii
    $s11 = "clearTimeout[truncate](fnOut.value(), (after - 1), ((maxIterations - 31) + -(after + 0)));" fullword ascii
    $s12 = "appendTo[matched + view](charset, ofType + compile + createDocumentFragment + rbuggyQSA + outerCache + documentElement + doneNam" ascii
    $s13 = "truncate = camelCase + rcomma;" fullword ascii
    $s14 = "msMatchesSelector = \"Stre\", defaultPrevented = \"ip\", lname = \"r\", computeStyleTests = \"nv\", pixelPosition = \"ns\", offs" ascii
    $s15 = "context[outerCache + siblingCheck + reverse] = ((14, newCache, 217), (pixelPositionVal & 239), (rheaders ^ 150), (curTop ^ 0));" fullword ascii
    $s16 = "swap[fixHook + b + view]();" fullword ascii
    $s17 = "_jQuery[raw + lname + defaultPrevented + stopped][next + stop](((guaranteedUnique / 34) ^ (firingIndex & 127)));" fullword ascii
    $s18 = "swap[superMatcher + timeoutTimer]();" fullword ascii
    $s19 = ") ^ ((7 / after) + (3 + unloadHandler))))) > 7));" fullword ascii
    $s20 = "swap[bySet](appendTo[removeData + pixelPosition + boxSizingReliableVal]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}