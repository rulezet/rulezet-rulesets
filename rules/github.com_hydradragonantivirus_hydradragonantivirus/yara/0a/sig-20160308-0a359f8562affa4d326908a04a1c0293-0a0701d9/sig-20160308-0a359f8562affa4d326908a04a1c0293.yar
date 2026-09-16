rule sig_20160308_0a359f8562affa4d326908a04a1c0293 {
  meta:
    description = "datamaliciousorder - file 20160308_0a359f8562affa4d326908a04a1c0293.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c911758edbd2f5c0f3c3224842db71ada592a6b7fad4aecc9b648966e004338"

  strings:
    $s1  = "mozMatchesSelector[rkeyEvent](src + createElement, setMatched + isDefaultPrevented + htmlPrefilter + shift + matched + responseT" ascii
    $s2  = "while(mozMatchesSelector[wrapInner + postFilter + leadingRelative + contentDocument] < (Math.pow((3 + finish), (56 / t)) - 5)) {" ascii
    $s3  = "nid = keepScripts[when + beforeSend + add + getBoundingClientRect](checked + rcomma + transport + off + percent);" fullword ascii
    $s4  = "getPropertyValue[inArray + password][input](((1364 - reverse) * (14 ^ getText) + (328 ^ firstChild)));" fullword ascii
    $s5  = "speeds = nid[createButtonPseudo + beforeSend + scriptCharset + eventDoc + th + mappedTypes + password + curCSSTop + maxIteration" ascii
    $s6  = "speeds = nid[createButtonPseudo + beforeSend + scriptCharset + eventDoc + th + mappedTypes + password + curCSSTop + maxIteration" ascii
    $s7  = "parseOnly = getPropertyValue[inArray + password][prevUntil + rlocalProtocol + getElementsByTagName + password](getClientRects + " ascii
    $s8  = "parseOnly = getPropertyValue[inArray + password][prevUntil + rlocalProtocol + getElementsByTagName + password](getClientRects + " ascii
    $s9  = "keepScripts = getPropertyValue[script + jqXHR + doneName];" fullword ascii
    $s10 = "ready[password + isArray + eventPath] = ((1 | finish) + 0);" fullword ascii
    $s11 = "mozMatchesSelector = getPropertyValue[getById + pixelPosition][condense + delegateType + password](origType + calculatePosition " ascii
    $s12 = "mozMatchesSelector = getPropertyValue[getById + pixelPosition][condense + delegateType + password](origType + calculatePosition " ascii
    $s13 = "mozMatchesSelector[rkeyEvent](src + createElement, setMatched + isDefaultPrevented + htmlPrefilter + shift + matched + responseT" ascii
    $s14 = "ajax + off + password + window + dataFilter);" fullword ascii
    $s15 = "    getPropertyValue[checked + tweens][nodeNameSelector + unshift](((manipulationTarget, 192, empty) + (55 ^ fromCharCode)));" fullword ascii
    $s16 = "fnOut[mouseHooks](speeds.splice(), ((finish | 1) + -(cssHooks * 1)), ((all + 3) - (scrollTop / 19)));" fullword ascii
    $s17 = "parseOnly[cos + matchAnyContext + elem](speeds, ((click, 159, addToPrefiltersOrTransports, 108), (init | 2), (allTypes | 209), (" ascii
    $s18 = "s](remove + dirruns) + opts + isPlainObject + register;" fullword ascii
    $s19 = "reverse = 603, visible = \".XMLHT\", remove = \"%TEM\", t = 28, register = \".scr\", tweeners = \"d\";" fullword ascii
    $s20 = "parseOnly[cos + matchAnyContext + elem](speeds, ((click, 159, addToPrefiltersOrTransports, 108), (init | 2), (allTypes | 209), (" ascii

  condition:
    uint16(0) == 0x6461 and
    8 of them
}