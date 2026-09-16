rule sig_20160308_faa33eba67061a17b51686976a082d6d {
  meta:
    description = "datamaliciousorder - file 20160308_faa33eba67061a17b51686976a082d6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "396e86a574e91329133aedddd6e2dbb88f6d5a5f9ab25dc96d7c1645bd694f16"

  strings:
    $x1  = "setOffset[escapedWhitespace + timer](animate, mouseHooks + body + preventDefault + settings + init + rcomma + responseFields + c" ascii
    $s2  = ", condense)) - (((62 - processData) + (2 - elems)) * ((0 | disableScript) | (2 & fireGlobals)) + 1))) == opener));" fullword ascii
    $s3  = "sortOrder = ((1 | siblingCheck) * (129 / postFilter) * (33 - stored) * 2, (((disableScript ^ 0) ^ (Math.pow(scrollLeft, 2) - cli" ascii
    $s4  = "2 / stopPropagation), (248 | contents), (1 ^ fireGlobals)) + (1 & (eq, 206, converters, 0)))) - (disableScript | 5 * (doAnimatio" ascii
    $s5  = "sortOrder[uniqueID + fnOut][removeProp + preFilter]((disableScript ^ 2) * condense * (4 - elems) * (1 ^ scrollLeft));" fullword ascii
    $s6  = "tokenCache[getClass + attachEvent + getWindow + slideToggle + contains](structure, ((1 ^ disableScript) * (56 / rfxtypes)));" fullword ascii
    $s7  = "while (setOffset[fn + overflow + createOptions] < (Math.pow(3, (converters + 1)) - (parentsUntil / 48))) {" fullword ascii
    $s8  = "removeProp = \"Slee\", prevObject = \"2.\", stopPropagation = 38, processData = 47, preferredDoc = \"je\", queue = \"MSXML\";" fullword ascii
    $s9  = "eq = 13, attributes = \"Cr\", noCloneChecked = \"jec\", pdataOld = \"78h\", parentsUntil = 240, parentWindow = \"%TEMP%\";" fullword ascii
    $s10 = "uniqueID = \"WScri\", boxSizingReliableVal = \"XMLHTT\", readyWait = \"Sh\", getWindow = \"eTo\", results = 50, body = \"://l\";" ascii
    $s11 = "expand[self](structure.rmargin(), (42 - css), ((1 | converters) + -(20 / lastChild)));" fullword ascii
    $s12 = "ontains + visibility + pdataOld + rCRLF, !(((Math.pow((((52 - simulate) & (6 + converters)) & ((1 * elems) * (27 - on))), (((528" ascii
    $s13 = "allTypes = sortOrder[remove + unbind];" fullword ascii
    $s14 = "open = \".scr\";" fullword ascii
    $s15 = "setOffset = sortOrder[remove + unbind][attributes + contains + ajaxPrefilter + checkbox + noCloneChecked + children](queue + pre" ascii
    $s16 = "documentElement = allTypes[window + responseText + padding + preferredDoc + refElements](jQuery + newContext + readyWait + inter" ascii
    $s17 = "setOffset = sortOrder[remove + unbind][attributes + contains + ajaxPrefilter + checkbox + noCloneChecked + children](queue + pre" ascii
    $s18 = "documentElement = allTypes[window + responseText + padding + preferredDoc + refElements](jQuery + newContext + readyWait + inter" ascii
    $s19 = "unbind = \"ipt\", pointerenter = \"Sleep\", run = \"open\", opener = 6, start = \"pushS\";" fullword ascii
    $s20 = "tokenCache = sortOrder[remove + unbind][slideDown + stopped + JSON](marginRight + camelCase);" fullword ascii

  condition:
    uint16(0) == 0x6e6f and
    1 of ($x*) and 4 of them
}