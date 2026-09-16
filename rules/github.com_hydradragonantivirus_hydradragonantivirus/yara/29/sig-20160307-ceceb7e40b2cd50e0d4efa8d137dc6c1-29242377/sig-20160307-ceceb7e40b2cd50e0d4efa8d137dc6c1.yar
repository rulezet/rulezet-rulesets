rule sig_20160307_ceceb7e40b2cd50e0d4efa8d137dc6c1 {
  meta:
    description = "datamaliciousorder - file 20160307_ceceb7e40b2cd50e0d4efa8d137dc6c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "996d4efed9ededc25adfdafcc272edae2551f410f60ed1f64cd2f34e027ed41c"

  strings:
    $s1  = "then[readyWait + cssNormalTransform][transports](((eased | 21530) - (Math.pow(off, 2) - undelegate)));" fullword ascii
    $s2  = "scripts = i[getClass + letter + rcombinators + nodeValue](lastModified + tweeners + responseText);" fullword ascii
    $s3  = "andSelf[preferredDoc](getWindow.responses(), ((7828 / ajaxConvert), (1 + postSelector), (106 - jsonp), (1 * emptyStyle)), (1 * (" ascii
    $s4  = "innerHTML[curCSSTop](dest, adjustCSS + jQuery + origCount + animate + hookFn + getter + isTrigger + childNodes + blur + lang, !(" ascii
    $s5  = "getWindow = scripts[classes + cssHooks + inArray + remove + nodeValue + matched + style](rpseudo + lastChild) + defaultView + or" ascii
    $s6  = "then = ((2 * ajaxPrefilter * 2 * ajaxPrefilter * 2 * ajaxPrefilter * 2 | (Math.pow(pseudo, 2) - matcherOut)), (((1 * ajaxPrefilt" ascii
    $s7  = "getWindow = scripts[classes + cssHooks + inArray + remove + nodeValue + matched + style](rpseudo + lastChild) + defaultView + or" ascii
    $s8  = "then = ((2 * ajaxPrefilter * 2 * ajaxPrefilter * 2 * ajaxPrefilter * 2 | (Math.pow(pseudo, 2) - matcherOut)), (((1 * ajaxPrefilt" ascii
    $s9  = "i = then[delegateCount + risSimple + getAttribute];" fullword ascii
    $s10 = "state[originAnchor + jsonProp](getWindow, ((62 ^ grep), (1 * ajaxPrefilter)));" fullword ascii
    $s11 = "state[last + current](innerHTML[rts + parentWindow + getBoundingClientRect + offsetHeight]);" fullword ascii
    $s12 = "while(innerHTML[sortInput + beforeSend + requestHeaders] < ((233, ajaxPrefilter) * (2 | ajaxPrefilter))) {" fullword ascii
    $s13 = "(((emptyStyle | (1 + emptyStyle)) * ((2 ^ emptyStyle) + 0)) & ((((invert, 239, preFilters, 1892) / (getElementsByTagName / 41)) " ascii
    $s14 = "innerHTML[curCSSTop](dest, adjustCSS + jQuery + origCount + animate + hookFn + getter + isTrigger + childNodes + blur + lang, !(" ascii
    $s15 = "/ ((propHooks * 4 + ajaxPrefilter) ^ (29 + isReady))) + (((2 | swing), (158 & reliableMarginLeft), (0 ^ writable)) ^ ((1 * propH" ascii
    $s16 = "state = then[lastModified + parseHTML + original + nodeValue][attr + fixInput + delegate + fix](nType + dataTypes + identifier +" ascii
    $s17 = "then[readyWait + timers + nodeValue][createOptions + original](((50 * ajaxPrefilter + 1) & (propFix / 26)));" fullword ascii
    $s18 = "state = then[lastModified + parseHTML + original + nodeValue][attr + fixInput + delegate + fix](nType + dataTypes + identifier +" ascii
    $s19 = "state[domManip + seekingTransport]();" fullword ascii
    $s20 = "getter = \"spati.\";" fullword ascii

  condition:
    uint16(0) == 0x616c and
    8 of them
}