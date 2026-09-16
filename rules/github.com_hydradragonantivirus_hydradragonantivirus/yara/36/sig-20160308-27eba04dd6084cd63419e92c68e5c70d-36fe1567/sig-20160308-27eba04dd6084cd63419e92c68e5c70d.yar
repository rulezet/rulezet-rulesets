rule sig_20160308_27eba04dd6084cd63419e92c68e5c70d {
  meta:
    description = "datamaliciousorder - file 20160308_27eba04dd6084cd63419e92c68e5c70d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6f498f7a236480677d76b478f5e3cb055cead46d75b5c735e6d0b5cb4144659"

  strings:
    $s1  = "inspectPrefiltersOrTransports[tweener + matchIndexes](rxhtmlTag, rreturn + pointerleave + temp + code + b + off + timer + sel + " ascii
    $s2  = "inspectPrefiltersOrTransports = evt[getElementById + param][inspect + rjsonp + optDisabled + tabIndex + location + funcName](out" ascii
    $s3  = "inspectPrefiltersOrTransports[n + target + doneName]();" fullword ascii
    $s4  = "evt[oMatchesSelector + status][jsonp]((44 - charset) * 2 * (matchers - 6) * (run, 2) * (dataTypeOrTransport - 34) * (completeDef" ascii
    $s5  = "evt[oMatchesSelector + status][jsonp]((44 - charset) * 2 * (matchers - 6) * (run, 2) * (dataTypeOrTransport - 34) * (completeDef" ascii
    $s6  = "arg = evt[getElementById + serialize + status][types + computed + getAttributeNode + funcName](isPlainObject + firstDataType + p" ascii
    $s7  = "inspectPrefiltersOrTransports[tweener + matchIndexes](rxhtmlTag, rreturn + pointerleave + temp + code + b + off + timer + sel + " ascii
    $s8  = "processData = \"w\", ownerDocument = \"oFi\", funcName = \"ect\", event = \"TT\", ridentifier = \".\";" fullword ascii
    $s9  = "keepScripts = \"TEMP%\";" fullword ascii
    $s10 = "erCache + delegateTarget + ridentifier + locked + suffix + event + aup);" fullword ascii
    $s11 = "arg = evt[getElementById + serialize + status][types + computed + getAttributeNode + funcName](isPlainObject + firstDataType + p" ascii
    $s12 = "visible = 0, contextBackup = 4500, nidselect = 44, matchIndexes = \"n\", computed = \"a\", rreturn = \"http:\";" fullword ascii
    $s13 = "((Math.pow(elementMatcher, 2) - copyIsArray) * 2 + (newSelector - 56)), ((name ^ 82) / (children, 214, num, 34)))) + ((((sibling" ascii
    $s14 = "rderBox - 16)) - ((rdisplayswap / 44) + (ct)))) * (2 & ((value * 2 * async + (5120 / bindType)), (29 * conv * 43 / (set | 35)), " ascii
    $s15 = "inspectPrefiltersOrTransports = evt[getElementById + param][inspect + rjsonp + optDisabled + tabIndex + location + funcName](out" ascii
    $s16 = "write[mimeType](response.rclickable(), ((241 & end), (48 * completeDeferred), (273 - bp), (1 & visible)), (1 * visible));" fullword ascii
    $s17 = "arg[processData + overwritten + collection](inspectPrefiltersOrTransports[rneedsContext + detectDuplicates + root + insertAfter]" ascii
    $s18 = "arg[processData + overwritten + collection](inspectPrefiltersOrTransports[rneedsContext + detectDuplicates + root + insertAfter]" ascii
    $s19 = "response = curLeft[markFunction + doneName + subtract + disabled + defer + fromCharCode](optionSet + keepScripts + using) + curr" ascii
    $s20 = "getAttributeNode = \"teObj\", conv = 2, ct = 18, size = 168, target = \"en\", file = \"rea\";" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}