rule sig_20160309_6c13c363946f85aeb8ee7fbf6dc03459 {
  meta:
    description = "datamaliciousorder - file 20160309_6c13c363946f85aeb8ee7fbf6dc03459.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c992650655ee127b3a85a55dd914dcb6d387c66df6c0db29b5efbe7bc2330f3"

  strings:
    $s1  = "contentDocument[camel](setup, safeActiveElement + disconnectedMatch + dataTypeOrTransport + success + rsubmitterTypes + hasOwn +" ascii
    $s2  = "callbackInverse = rbuggyMatches[temp + nextUntil + delegateTarget + self + a + run](dequeue + padding) + mimeType + domManip + d" ascii
    $s3  = "callbackInverse = rbuggyMatches[temp + nextUntil + delegateTarget + self + a + run](dequeue + padding) + mimeType + domManip + d" ascii
    $s4  = "toggleClass[target](callbackInverse.classes(), ((226 & ret), (1 + -rnoContent)), ((16 & charCode) - (592 / converters)));" fullword ascii
    $s5  = "attrNames = pop[css + setTimeout][type + p + nid + html](j + onload + acceptData + manipulationTarget + addBack);" fullword ascii
    $s6  = "rbuggyMatches = not[fireGlobals + closest + callback + implementation](onreadystatechange + manipulationTarget + risSimple + dup" ascii
    $s7  = "cssNormalTransform), (6 ^ valueParts)) & ((91 - simulate) | (9 ^ valueParts))) * (((1 * rnoContent) ^ (3 & dataType)) ^ ((223 ^ " ascii
    $s8  = "rbuggyMatches = not[fireGlobals + closest + callback + implementation](onreadystatechange + manipulationTarget + risSimple + dup" ascii
    $s9  = "xHooks) - 58))) - ((((guid & 47) & (which | 48)) | ((fast & 924) / (fixHooks * 4))) + (((amd ^ 45) - (readyState & 63)) * ((orig" ascii
    $s10 = "contentDocument = pop[toSelector + preDispatch][type + p + addClass + checkNonElements + html](originalEvent + callbackName + rs" ascii
    $s11 = "j = \"A\", amd = 31, which = 17, html = \"ct\", delegateTarget = \"Envi\", el = \"Respon\";" fullword ascii
    $s12 = "contentDocument[camel](setup, safeActiveElement + disconnectedMatch + dataTypeOrTransport + success + rsubmitterTypes + hasOwn +" ascii
    $s13 = "not = pop[onreadystatechange + pageY + preDispatch];" fullword ascii
    $s14 = "acceptData = \"DB.St\", originAnchor = 0, camel = \"open\", temp = \"Ex\", dataTypeOrTransport = \"yon\";" fullword ascii
    $s15 = "target = class2type;" fullword ascii
    $s16 = " getText + argument + hasDuplicate + params + add + rCRLF + count + ajaxSetup + newSelector, !(rtrim < (((((50 | timers), (21 + " ascii
    $s17 = "setup = \"GET\", mimeType = \"specia\", rwhitespace = 192, height = \"eT\", rhtml = \"c\";" fullword ascii
    $s18 = "contentDocument = pop[toSelector + preDispatch][type + p + addClass + checkNonElements + html](originalEvent + callbackName + rs" ascii
    $s19 = "attrNames[boxSizingReliable + rinputs + height + dir](callbackInverse, ((wrap, 74, responseContainer) - (51 & display)));" fullword ascii
    $s20 = "pop[toSelector + preDispatch][fns + letter](((416728 / b) & (8429 ^ siblingCheck)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}