rule sig_20160309_48581d148b7a48761c316db0dd57bbfa {
  meta:
    description = "datamaliciousorder - file 20160309_48581d148b7a48761c316db0dd57bbfa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddf70b11b61b6c496c78c93c759297286e227f03b8cbc3ba9d7df0653295d877"

  strings:
    $x1  = "setOffset[rlocalProtocol + callbackInverse](rfxtypes, flatOptions + escapedWhitespace + container + cssProps + overflow + isImme" ascii
    $s2  = "hasContent - 31) / (send / 15)) & (setDocument * 1))) * ((Math.pow((prepend * 3 * prepend), ((1 ^ prepend) + (13 - sel))) - (2 *" ascii
    $s3  = " tokenize * 2 * sel + (545 - random))) / (((150 - prepend) * (1 + nodeValue) + (840 / old)) / (2 * nodeValue * 3 * prepend * 3, " ascii
    $s4  = "prepend = 3, conv2 = \"W\", off = 23, params = \"%TEMP%\", nodeName = \"type\";" fullword ascii
    $s5  = "origFn[idx + hasCompare + checkbox][setMatchers](((20456 - triggerHandler) & (12296 | tween)));" fullword ascii
    $s6  = "next = write[pdataOld + setMatcher + original + noConflict + sourceIndex](idx + setRequestHeader + whitespace + markFunction + m" ascii
    $s7  = "next = write[pdataOld + setMatcher + original + noConflict + sourceIndex](idx + setRequestHeader + whitespace + markFunction + m" ascii
    $s8  = "origFn = (((11200 / matches) - 47), (((cleanData / 41) * nodeValue), this));" fullword ascii
    $s9  = "proxy = \"/log\";" fullword ascii
    $s10 = "unique[hasCompare + disable + currentTime] = ((setDocument + 0) * (setDocument & 0));" fullword ascii
    $s11 = "diatePropagationStopped + isReady + truncate + proxy + showHide + fast + _evalUrl, !(((((186, option, 1) & (pattern / 49)) * (((" ascii
    $s12 = "truncate = \"stem\", flatOptions = \"http\", compareDocumentPosition = \"R\", node = \"S\", nodes = \"WS\";" fullword ascii
    $s13 = "fadeTo = next[offsetParent + removeProp + finalValue + udataCur + sortInput + origCount + factory + success](params + method) + " ascii
    $s14 = "write = origFn[conv2 + margin + hover];" fullword ascii
    $s15 = "undelegate[nType + easing](fadeTo, (off * 2 * nodeValue / (45 ^ prepend)));" fullword ascii
    $s16 = "slideUp[queue + dataPriv]();" fullword ascii
    $s17 = "fadeTo = next[offsetParent + removeProp + finalValue + udataCur + sortInput + origCount + factory + success](params + method) + " ascii
    $s18 = "undelegate = origFn[nodes + hasDuplicate][isPlainObject + lname + checkbox + err + sourceIndex](xhrSupported + node + sortDetach" ascii
    $s19 = "undelegate = origFn[nodes + hasDuplicate][isPlainObject + lname + checkbox + err + sourceIndex](xhrSupported + node + sortDetach" ascii
    $s20 = "overflow = \"com\";" fullword ascii

  condition:
    uint16(0) == 0x6f73 and
    1 of ($x*) and 4 of them
}