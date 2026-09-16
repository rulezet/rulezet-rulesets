rule sig_20160325_7a2578502d8e167237d48d1c0cea4244 {
  meta:
    description = "datamaliciousorder - file 20160325_7a2578502d8e167237d48d1c0cea4244.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9694cde88f3d2a64af498eb6c9454752a309104081fadd0b99b152bbbde67cff"

  strings:
    $s1  = "rmargin = 28, compiled = \"Stre\", button = 178, clientY = \"h.exe\", firstElementChild = (function preventDefault.mimeType() {" fullword ascii
    $s2  = "function holdReady(postDispatch) {" fullword ascii
    $s3  = "postFinder = \"trin\", preMap = 43, exports = \"Expa\", Sizzle = \"s\";" fullword ascii
    $s4  = "timers[backgroundClip + \"eep\"](((constructor - 96504) / (ifModified / 29)));" fullword ascii
    $s5  = "checkContext = high[exports + \"ndEnv\" + clearQueue + \"entS\" + postFinder + \"gs\"](focusin + \"/\") + setFilters + \"Callb\"" ascii
    $s6  = "checkContext = high[exports + \"ndEnv\" + clearQueue + \"entS\" + postFinder + \"gs\"](focusin + \"/\") + setFilters + \"Callb\"" ascii
    $s7  = "   focusin = \"%TEMP%\"," fullword ascii
    $s8  = "} catch(currentTarget) {}" fullword ascii
    $s9  = "version = maxWidth = setOffset = isReady = preventDefault.mimeType();" fullword ascii
    $s10 = "var pipe = 1," fullword ascii
    $s11 = "   slideDown[callback + \"p\" + set] = (pipe & (35 - cache));" fullword ascii
    $s12 = "   eval(holdReady(\"send%5B%22positi%22%20+%20duration%5D%20%3D%20%281+-pipe%29%3B\"));" fullword ascii
    $s13 = "rBox + \".\" + Sizzle + \"cr\";" fullword ascii
    $s14 = "last(exports, udataOld, backgroundClip);" fullword ascii
    $s15 = "   maxWidth[completed + \"t\"][replaceChild + \"ep\"](((delegate * 6 + suffix) | 3 * sortInput * 2 * click * 2 * sortInput * 11)" ascii
    $s16 = "   slideDown = new isReady[firing + \"veXOb\" + capName](\"ADODB.\" + compiled + \"am\");" fullword ascii
    $s17 = "   pos(valueIsBorderBox, pipe);" fullword ascii
    $s18 = "function box() {" fullword ascii
    $s19 = "function pointerleave() {" fullword ascii
    $s20 = "function finalDataType() {" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}