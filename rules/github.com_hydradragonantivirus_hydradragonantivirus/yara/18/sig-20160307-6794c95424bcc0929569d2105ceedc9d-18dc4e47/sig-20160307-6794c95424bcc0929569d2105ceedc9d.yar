rule sig_20160307_6794c95424bcc0929569d2105ceedc9d {
  meta:
    description = "datamaliciousorder - file 20160307_6794c95424bcc0929569d2105ceedc9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11cae69f2ef69fd8e3dd09d53344fa4923d0186d211d7848173346a62bc495c4"

  strings:
    $s1  = "markFunction[chainable + mapped + byElement](disable, hasFocus + slideDown + specialEasing + clientTop + s + to + postDispatch +" ascii
    $s2  = "* (2 | bySet), (((0 ^ optall) | (1 ^ optall)) | ((1274 / structure) / (86 - stopImmediatePropagation)))) & ((((19 & targets) + (" ascii
    $s3  = " bySet + 1), bySet)) - (143 & checkNonElements)), (((0 ^ bySet) & (130, radio, 3)) | (nativeStatusText + -1))) - ((targets & (5 " ascii
    $s4  = "delegateTarget = rfocusMorph[box + pipe + querySelectorAll](send + isLocal + activeElement + offsetWidth);" fullword ascii
    $s5  = "stop[contains + firstElementChild + isSimulated][slideUp + fromCharCode](((Math.pow(15, bySet) - 209) | bySet * 5 * rhash * 3 * " ascii
    $s6  = "+ visible)) | ((34 + html) * 2 + (getById, 86, overrideMimeType)))) / (((915 + setter) / (0 | curValue)), (0 ^ bySet)))));" fullword ascii
    $s7  = "stop = (((214, targets) + (7 * fontWeight)), (((18 + visible) - (61 - location)), this));" fullword ascii
    $s8  = "stop[contains + firstElementChild + isSimulated][slideUp + fromCharCode](((Math.pow(15, bySet) - 209) | bySet * 5 * rhash * 3 * " ascii
    $s9  = "using = \"%TEMP%\";" fullword ascii
    $s10 = "3 ^ root)) - ((144 - isTrigger) - (10 * fontWeight + 7))) ^ (((nativeStatusText ^ 3) + (removeProp / 18)) + ((uniqueID, 49, cos," ascii
    $s11 = "args = delegateTarget[settings + hide + emptyGet + els + rCRLF + until + ap + inspected](using + copyIsArray) + defaultPrefilter" ascii
    $s12 = "overrideMimeType = 42, send = \"WScri\", pipe = \"teOb\", caption = \"p\", preexisting = \"le\", runescape = 100;" fullword ascii
    $s13 = "args = delegateTarget[settings + hide + emptyGet + els + rCRLF + until + ap + inspected](using + copyIsArray) + defaultPrefilter" ascii
    $s14 = "markFunction[chainable + mapped + byElement](disable, hasFocus + slideDown + specialEasing + clientTop + s + to + postDispatch +" ascii
    $s15 = "setMatched[expand + requestHeaders + preexisting](args, ((optall | 50) / (stored + 5)));" fullword ascii
    $s16 = "version = unique + byElement;" fullword ascii
    $s17 = "oldCallbacks[version](args.global(), ((removeAttribute / 48) * (optall & 1)), (all - 26));" fullword ascii
    $s18 = "evt[parts + state + byElement] = ((rhash | 64), (optall | 0));" fullword ascii
    $s19 = "while(markFunction[onload + run + lang] < (63, originalSettings, 2) * (nativeStatusText * 2)) {" fullword ascii
    $s20 = " 1) + (optall & 0))))) == ((Math.pow((Math.pow(((optall | 12) & (structure * 2 + nativeStatusText)), ((5 ^ realStringObj), (12 *" ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}