rule sig_20160307_d3910af288e7128726626ae2a9906889 {
  meta:
    description = "datamaliciousorder - file 20160307_d3910af288e7128726626ae2a9906889.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69be91410d1a927a5e94aeed77162742a3d36b04cdb6dfcb3b9aeeae8a26083c"

  strings:
    $s1  = "margin[checkbox + original][border]((ridentifier - 27) * (compile + 1) * (fireGlobals - 42) * (Sizzle / 38) * (getter / 24) * (f" ascii
    $s2  = "margin[checkbox + original][border]((ridentifier - 27) * (compile + 1) * (fireGlobals - 42) * (Sizzle / 38) * (getter / 24) * (f" ascii
    $s3  = "empty[once + matchAnyContext + errorCallback + getScript + ret](src, ((6 + stateVal) - (12 / pdataCur)));" fullword ascii
    $s4  = "margin[jqXHR + letterSpacing][matchers + rkeyEvent](((getter / 15) * (setGlobalEval & 13) + (stateVal | 4)));" fullword ascii
    $s5  = "checkClone[udataCur](hasDuplicate, hasData + innerHTML + inspected + elems + finish + implementation + disable + cached + ajaxSe" ascii
    $s6  = "+ cacheURL) - (270 / getResponseHeader)) - ((1 ^ (pop, 2)) * ((parentOffset / 23) ^ (Math.pow(optgroup, 2) - access)))) / (Math." ascii
    $s7  = "delegate = \"typ\", getScript = (function Object.prototype.noop() {" fullword ascii
    $s8  = "pow((((4 | stateVal))), (((1 + compile) + 0) - stateVal)) - (((0 | compile) * (2 ^ stateVal)) | ((33 - resolveWith) * (0 ^ optgr" ascii
    $s9  = "checkContext = margin[headers + getAll + original];" fullword ascii
    $s10 = "overflowX = checkContext[removeClass + originalSettings + active + letterSpacing](checkbox + PI + keyCode + postFinder);" fullword ascii
    $s11 = "inalDataType - 5) * (success + 1) * (finalDataType & 5));" fullword ascii
    $s12 = "getter = 120, combinator = \"yst\", method = 250, appendChild = \"C\";" fullword ascii
    $s13 = "ttings + conditionFn + adjusted + padding, !(8 == (((stateVal | (182 / prevAll)) * ((0 | compile) * (42 / setGlobalEval)) * ((2 " ascii
    $s14 = "insertAfter = \"ad\", isSimulated = \"s\", rnative = \"L\", ontype = \"te\", raw = \".scr\", border = \"Sleep\";" fullword ascii
    $s15 = "while(checkClone[parents + insertAfter + combinator + dest] < (1 * (success + 2))) {" fullword ascii
    $s16 = "getClass[createPseudo + special] = stateVal;" fullword ascii
    $s17 = "empty[rchecked + optDisabled]();" fullword ascii
    $s18 = "dataType[delegate + winnow] = (stateVal | 1);" fullword ascii
    $s19 = "headers = \"WScr\", Sizzle = 190, cssNormalTransform = \"m\", ownerDocument = \"ML\", getElementsByClassName = \"Run\", originAn" ascii
    $s20 = "checkClone = margin[checkbox + original][appendChild + parents + handle + addBack + letterSpacing](contexts + rnative + noBubble" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}