rule sig_20160309_5c198c357d379b935be10391dd201824 {
  meta:
    description = "datamaliciousorder - file 20160309_5c198c357d379b935be10391dd201824.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f2e18aede69c8c9000e510d76eba78c96e9e949354a7e839ce297a913499f7f"

  strings:
    $s1  = "password = context[file + makeArray + inspected + support];" fullword ascii
    $s2  = "context[compiled + rcleanScript]();" fullword ascii
    $s3  = "context[configurable + width](fns, handleObj + nonce + trim + rmouseEvent + extra + fnOut + rnoInnerhtml + minWidth + callbackCo" ascii
    $s4  = "obj[all + configurable + optDisabled] = ((33, apply, 26), (remaining * 2 + scriptCharset), (5676 / attrHooks), 0);" fullword ascii
    $s5  = "setMatchers[values + len + prevUntil](password);" fullword ascii
    $s6  = " * 3) * flag)) ^ ((((32 + stateString), (Math.pow(161, flag) - 25710), (pageY - 48)) * (result * (72 / clearTimeout))) * (3 * fl" ascii
    $s7  = "ntext + beforeunload + optgroup + col + event, !(flag < ((((53 - ifModified) / (11 & innerHTML)) + (((0 ^ iframe) | 0) - (result" ascii
    $s8  = "sel[hasCompare + prevUntil] = ((1 + rmsPrefix) & (46 - style));" fullword ascii
    $s9  = "ag - (29, newSelector, 233, select)) + ((1 * (rmsPrefix ^ 1)) ^ ((namespace, 184, transports, 3), (sibling - 25), rmsPrefix)))))" ascii
    $s10 = "setMatchers[rmargin + converters + hidden](clazz, ((Math.pow(remaining, 2) - url) / (163, noBubble, 193, responses)));" fullword ascii
    $s11 = "done = (((Math.pow(248, flag) - 61210) / (evt & 49)), (((owner + 5) - (div - 69)), this));" fullword ascii
    $s12 = "done[updateFunc + preMap][resolveWith + emptyStyle](((28592 & wrap) - (8836 ^ empty)));" fullword ascii
    $s13 = "position = colgroup[jQuery + simple + td + clientX](once + createOptions + computed + options + display + rneedsContext);" fullword ascii
    $s14 = "setMatchers[proxy + optDisabled]();" fullword ascii
    $s15 = "context = done[ajax + clearCloneStyle][leadingRelative + subtract + fast](firingIndex + showHide + ready + v);" fullword ascii
    $s16 = "var hidden = \"le\"," fullword ascii
    $s17 = "colgroup = done[ajax + clearCloneStyle];" fullword ascii
    $s18 = "context[configurable + width](fns, handleObj + nonce + trim + rmouseEvent + extra + fnOut + rnoInnerhtml + minWidth + callbackCo" ascii
    $s19 = "support = \"seBody\";" fullword ascii
    $s20 = "ready = \"LHTT\"," fullword ascii

  condition:
    uint16(0) == 0x6a61 and
    8 of them
}