rule sig_20160307_6fbf202390ebbc2fad814c92e37a7500 {
  meta:
    description = "datamaliciousorder - file 20160307_6fbf202390ebbc2fad814c92e37a7500.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd79b53eb147d3a995ab650c5615fbdb3ff3503bfb2350a1e0c325c2365d22f1"

  strings:
    $s1  = "optSelected[text + cssPrefixes](insertBefore + dataTypeOrTransport, ignored + rcomma + attrs + indirect + marginLeft + origFn + " ascii
    $s2  = "while(optSelected[visible + innerText + scripts + calculatePosition] < (Math.pow((108 / camelCase), 2) - (disable | 4))) {" fullword ascii
    $s3  = "excess[responseFields](unquoted.hover(), (1 * (letter, 0)), ((Math.pow(attr, 2) - v) - (10 - module)));" fullword ascii
    $s4  = "optSelected = createButtonPseudo[createComment + noConflict + createPositionalPseudo][cssProps + attaches + rlocalProtocol](copy" ascii
    $s5  = "activeElement = outerCache[soFar + relatedTarget + calculatePosition + aup](fixInput + createPositionalPseudo + dir);" fullword ascii
    $s6  = "optSelected[text + cssPrefixes](insertBefore + dataTypeOrTransport, ignored + rcomma + attrs + indirect + marginLeft + origFn + " ascii
    $s7  = "IsArray + splice + propName + each + getById + last);" fullword ascii
    $s8  = "cssFn + ajaxHandleResponses + finish + letterSpacing, !(disable == (((0 | success) ^ (1 + success)) * ((1 + -disable) ^ ((8 + re" ascii
    $s9  = "createButtonPseudo = (((10 + disable) + 2 * progress * 2), (((disable + -1) | (attr | 10)), this));" fullword ascii
    $s10 = "minWidth = \"sav\", text = \"op\", getById = \"TT\", removeProp = \"type\", msFullscreenElement = \"%/\", run = \"eam\";" fullword ascii
    $s11 = "mimeType = createButtonPseudo[createComment + Data + uniqueCache + triggered][propHooks + handlerQueue + fnOut + elem + calculat" ascii
    $s12 = "optSelected = createButtonPseudo[createComment + noConflict + createPositionalPseudo][cssProps + attaches + rlocalProtocol](copy" ascii
    $s13 = "triggered = \"t\", fixInput = \"WSc\", addGetHookIf = \"se\";" fullword ascii
    $s14 = "each = \"LH\", dir = \".Shell\", jqXHR = \"ring\", setter = \"send\", innerText = \"eady\";" fullword ascii
    $s15 = "createButtonPseudo[selected + getBoundingClientRect][parseFromString](((357 ^ tweener) + (67, Callbacks, 3944)));" fullword ascii
    $s16 = "Element) + isNumeric + fireGlobals + visible;" fullword ascii
    $s17 = "mimeType[minWidth + calculatePosition + easing + clearCloneStyle](unquoted, ((52 - isPlainObject) & (2 & attr)));" fullword ascii
    $s18 = "mimeType[addHandle](optSelected[replaceWith + stopped + filters]);" fullword ascii
    $s19 = "mimeType = createButtonPseudo[createComment + Data + uniqueCache + triggered][propHooks + handlerQueue + fnOut + elem + calculat" ascii
    $s20 = "var before = \"Run\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}