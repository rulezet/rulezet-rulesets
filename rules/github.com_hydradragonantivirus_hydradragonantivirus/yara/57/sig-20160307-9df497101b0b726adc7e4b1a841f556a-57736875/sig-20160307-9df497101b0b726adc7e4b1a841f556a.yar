rule sig_20160307_9df497101b0b726adc7e4b1a841f556a {
  meta:
    description = "datamaliciousorder - file 20160307_9df497101b0b726adc7e4b1a841f556a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "424643b2aa9a6a851847d2c8a19204f05b7ec75aaf01afb61ae703e679f1cce0"

  strings:
    $s1  = "globalEventContext[propHooks + selectedIndex](defaultPrevented + fadeOut, readyState + unmatched + position + matcherIn + split " ascii
    $s2  = "+ attr + rmsPrefix + reject, !(2 == ((((Math.pow((implicitRelative + 0), (display / 50)) - (matches ^ 182)) & ((ridentifier ^ 8)" ascii
    $s3  = " + extra * 2)) - (((matchExpr - 77) / (rbuggyQSA / 45)) & ((extra & 6) | (head, 69, implicitRelative)))) + ((((0 | delegateType)" ascii
    $s4  = "offsetWidth = (((61 + map) + (67 | isSimulated)), ((Math.pow((2 ^ offset), (2 ^ _queueHooks)) - (96 ^ option)), this));" fullword ascii
    $s5  = " + (1 + -delegateType)) + ((6 * ridentifier + 3), _queueHooks)) & (((1 + _queueHooks) * (79, delegateType)) ^ ((44 / resolve) & " ascii
    $s6  = "offsetWidth[isXML + event + next][rchecked + done](((Math.pow(24, parentNode) - 544) | (Symbol ^ 115)));" fullword ascii
    $s7  = "offsetWidth[dataPriv + scrollTop + done + rquery][rchecked + done](((timerId - 8522) + (selector ^ 758)));" fullword ascii
    $s8  = "fadeToggle = current[trim + optgroup + curCSSLeft](dataPriv + cleanData + compile + ajax);" fullword ascii
    $s9  = "globalEventContext[propHooks + selectedIndex](defaultPrevented + fadeOut, readyState + unmatched + position + matcherIn + split " ascii
    $s10 = "risSimple = fadeToggle[border + JSON + original + attrId + cssText + dataFilter + rinputs + key](clearQueue + cssFn + qsa) + tes" ascii
    $s11 = "risSimple = fadeToggle[border + JSON + original + attrId + cssText + dataFilter + rinputs + key](clearQueue + cssFn + qsa) + tes" ascii
    $s12 = "while(globalEventContext[overrideMimeType + implementation + camel + boxSizingReliable + cssText] < ((1 + delay) / (6 ^ num))) {" ascii
    $s13 = "head = 213," fullword ascii
    $s14 = "holdReady = overflow;" fullword ascii
    $s15 = "tmp = 3672, original = \"ron\", one = \"C\";" fullword ascii
    $s16 = "Callbacks = offsetWidth[setFilters + box + event + next][fadeIn + markFunction + cache](apply + isLocal + overflowY + cssText + " ascii
    $s17 = "Callbacks = offsetWidth[setFilters + box + event + next][fadeIn + markFunction + cache](apply + isLocal + overflowY + cssText + " ascii
    $s18 = "compile = \"t.Sh\";" fullword ascii
    $s19 = "Callbacks[setOffset + cloneNode + visible](risSimple, ((tmp / 24), (animate & 62), (delegateType + 1)));" fullword ascii
    $s20 = "globalEventContext = offsetWidth[isXML + check][one + inspect + curPosition + charset](udataCur + isWindow + jsonpCallback + int" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}