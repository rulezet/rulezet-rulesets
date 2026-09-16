rule sig_20160311_6f49453d2e87db2840704ccc293361b7 {
  meta:
    description = "datamaliciousorder - file 20160311_6f49453d2e87db2840704ccc293361b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61f8aeb4f6110ece27142f9e69aebbad45a3634fc37ceec20e0ce7fb677fa340"

  strings:
    $s1  = "condense[currentValue + \"e\" + delegateType](\"G\" + left, \"http:/\".safeActiveElement() + node + \"mom\" + overflowX + \"om/0" ascii
    $s2  = "th.pow(((curTop, 7, cssText) * (4 | progress) + 7), (postDispatch + (206, errorCallback, 0))) - (rcomma, (127 & origFn), (612 / " ascii
    $s3  = "requestHeaders = \"%TEMP%\";" fullword ascii
    $s4  = "andSelf), (10340 | rsubmittable)))) / ((((100 / dirrunsUnique) & (103, cleanData, 5)) * ((Math.pow(define, 2) - uid) - 2 * exces" ascii
    $s5  = "prev[getElementsByClassName + \"n\"](event.safeActiveElement(((Math.pow(27, postDispatch) - 697) + (elementMatchers, 57))), (pro" ascii
    $s6  = "appendChild = inspectPrefiltersOrTransports[maxWidth + \"t\"][matcher + \"Object\".safeActiveElement()](th + \".Str\" + pos);" fullword ascii
    $s7  = "win = inspectPrefiltersOrTransports[\"WSc\" + root];" fullword ascii
    $s8  = "condense = inspectPrefiltersOrTransports[optionSet + \"ipt\".safeActiveElement()][cssShow + \"eObj\" + offsetParent](\"MSXML2\" " ascii
    $s9  = "event = open[\"Expa\" + origCount + \"ironme\".safeActiveElement() + unmatched + \"ngs\"](requestHeaders + \"/\") + removeData +" ascii
    $s10 = "event = open[\"Expa\" + origCount + \"ironme\".safeActiveElement() + unmatched + \"ngs\"](requestHeaders + \"/\") + removeData +" ascii
    $s11 = "inspectPrefiltersOrTransports = ((2 * capName * 7 * progress * 7 * postDispatch * 2 / (dir & 61)), (select | 3) * postDispatch *" ascii
    $s12 = "inspectPrefiltersOrTransports = ((2 * capName * 7 * progress * 7 * postDispatch * 2 / (dir & 61)), (select | 3) * postDispatch *" ascii
    $s13 = "condense = inspectPrefiltersOrTransports[optionSet + \"ipt\".safeActiveElement()][cssShow + \"eObj\" + offsetParent](\"MSXML2\" " ascii
    $s14 = "condense[currentValue + \"e\" + delegateType](\"G\" + left, \"http:/\".safeActiveElement() + node + \"mom\" + overflowX + \"om/0" ascii
    $s15 = "appendChild[selected + \"ToF\".safeActiveElement() + owner](event, ((propFilter & 1) * (propFilter + 1)));" fullword ascii
    $s16 = " (2 | propFilter), eval(\"t\" + then + \"i\".safeActiveElement() + attr));" fullword ascii
    $s17 = "open = win[\"Create\" + adjusted + \"t\".safeActiveElement()](optionSet + \"ipt.Sh\" + backgroundClip);" fullword ascii
    $s18 = "condense[\"se\".safeActiveElement() + delegateType + \"d\"]();" fullword ascii
    $s19 = "ilter * 0), (select));" fullword ascii
    $s20 = "s) + ((4 | select))) * 2)) == implicitRelative));" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}