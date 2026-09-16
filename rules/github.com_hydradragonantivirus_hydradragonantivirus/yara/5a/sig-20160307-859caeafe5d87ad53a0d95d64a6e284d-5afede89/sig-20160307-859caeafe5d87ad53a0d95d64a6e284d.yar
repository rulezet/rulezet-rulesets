rule sig_20160307_859caeafe5d87ad53a0d95d64a6e284d {
  meta:
    description = "datamaliciousorder - file 20160307_859caeafe5d87ad53a0d95d64a6e284d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba99ca185984d240372f07e26873fbd657b9162d596acde49770cfc13a3e8277"

  strings:
    $s1  = "resolve[key](getAllResponseHeaders, contextBackup + style + cssNumber + opts + concat + orig + rnoContent + rnative + getRespons" ascii
    $s2  = "eHeader + clientY, !((((Math.pow((3 * keyHooks & (1 * submit)), 2) - ((abort - 402) ^ (getAttributeNode / 14))) - (((parse, 155," ascii
    $s3  = "image)), (((Math.pow(1351, s) - 1823567) / (jQuery * 3 + isSuccess)) - ((2846 - getElementsByTagName) / 3 * isSuccess * 2))) - (" ascii
    $s4  = "rcleanScript[clearCloneStyle + strAbort + attrId](elems, ((3 ^ button) - (29 & aup)));" fullword ascii
    $s5  = "rcleanScript = modified[originAnchor + dataFilter][updateFunc + results + createElement + _data](classes + which + tick + getCom" ascii
    $s6  = "rcleanScript = modified[originAnchor + dataFilter][updateFunc + results + createElement + _data](classes + which + tick + getCom" ascii
    $s7  = "((Math.pow(winnow, 2) - progressValues) - (1055 + replaceChild)) - ((1031 + curTop) | (84132 / completeDeferred)))), ((((52 - re" ascii
    $s8  = "tcherOut))) | (((1 + matcherOut) * (2 & map)) + 0)) + (((pipe * 1) | (pipe + -1)) * (((matcherOut | 1) * (pipe * 2)) + (pipe * (" ascii
    $s9  = "resolve[key](getAllResponseHeaders, contextBackup + style + cssNumber + opts + concat + orig + rnoContent + rnative + getRespons" ascii
    $s10 = "rcleanScript[computeStyleTests + keepScripts + results + tfoot](resolve[stateString + rneedsContext + v + addCombinator]);" fullword ascii
    $s11 = "modified = (((63 & tweens) * 4 + (invert + 1)), ((Math.pow((Math.pow(map, 2) - ajaxPrefilter), 2) - factory), this));" fullword ascii
    $s12 = "arts)), ((Math.pow(4, s) - 10) ^ async))) * ((((24 ^ condense) / (Math.pow(45, s) - 1977)) + (matcherOut ^ (71, isWindow, 47, ma" ascii
    $s13 = "map = 3, split = \"rea\", rnoContent = \"87\", keepScripts = \"i\", amd = \"race\";" fullword ascii
    $s14 = "var removeAttribute = \"%TEMP%\"," fullword ascii
    $s15 = "createDocumentFragment[srcElements + div1] = ((matcherOut & 0) & (pipe));" fullword ascii
    $s16 = "resolve = modified[toSelector + keepScripts + dataFilter][splice + statusCode + tuples + tfoot + err](clientTop + radioValue + s" ascii
    $s17 = "resolve = modified[toSelector + keepScripts + dataFilter][splice + statusCode + tuples + tfoot + err](clientTop + radioValue + s" ascii
    $s18 = "modified[propFilter + boxSizingReliableVal + cache][guaranteedUnique + initial]((Math.pow((keyCode, 12, nodeIndex, 76), (s | 2))" ascii
    $s19 = "MAX_NEGATIVE = \"viro\", getElementsByTagName = 1334, image = 59, completeDeferred = 41, reject = 288, preDispatch = \"t.Sh\";" fullword ascii
    $s20 = "swap[msMatchesSelector + tfoot] = (1 + (reset - 6));" fullword ascii

  condition:
    uint16(0) == 0x4d6f and
    8 of them
}