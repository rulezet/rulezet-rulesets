rule sig_20160307_5f5fc367f131b07ef59d545a22667be9 {
  meta:
    description = "datamaliciousorder - file 20160307_5f5fc367f131b07ef59d545a22667be9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fd2d46931c71d2e326ac27abea17896ff79b024492033e7605e1407b3e2aec2"

  strings:
    $x1  = "offsetHeight[originalSettings + stopQueue + input + caption](ajaxTransport + replaceAll, matchesSelector + condense + hookFn + r" ascii
    $x2  = "g + 7)) | ((setAttribute & 500) / (keepScripts & 30))) / ((delegateType & (Math.pow(9, targets) - 66)) ^ ((msg & 1) + (delay, 3)" ascii
    $s3  = "innerText = ((Math.pow((203 - bool), (1 + msg)) - (2197 ^ random)), (((3 * targets + 1) & (slideUp + 3)), this));" fullword ascii
    $s4  = "username[rts + fired](propFix, ((targets ^ 0) ^ (msg * 0)));" fullword ascii
    $s5  = "itRelative / 9) & targets * 3)) + (((superMatcher & 255), (errorCallback, 92, apply), (60 - disable), (27 - risSimple)) * ((1 + " ascii
    $s6  = "jsonp + firstElementChild + matcher + letter + resolveWith + createInputPseudo, !((((((cssHooks ^ 2) * (targets & 3)) | ((implic" ascii
    $s7  = "username[siblingCheck](offsetHeight[urlAnchor + readyWait + curOffset + restoreScript + until]);" fullword ascii
    $s8  = "username = innerText[flatOptions + rheader][reverse + fireWith + deep + values](implementation + ontype + elementMatchers + sour" ascii
    $s9  = "username = innerText[flatOptions + rheader][reverse + fireWith + deep + values](implementation + ontype + elementMatchers + sour" ascii
    $s10 = "while (offsetHeight[DOMParser + checkDisplay] < (Math.pow((30 / prependTo), 2) - (original / 6))) {" fullword ascii
    $s11 = "propFix = rootjQuery[getAll + caption + setter + current + input + delegateCount + dir + nonce](handleObj + optall) + rreturn + " ascii
    $s12 = "propFix = rootjQuery[getAll + caption + setter + current + input + delegateCount + dir + nonce](handleObj + optall) + rreturn + " ascii
    $s13 = "urlAnchor = \"Re\", originalProperties = \"C\", wrapInner = \"jec\", initialInUnit = 33, keepScripts = 28, notify = \"WS\";" fullword ascii
    $s14 = "safeActiveElement + a + high;" fullword ascii
    $s15 = "offsetHeight = innerText[strAbort + fontWeight][originalProperties + setDocument + toggle + wrapInner + origName](pointerenter +" ascii
    $s16 = "offsetHeight = innerText[strAbort + fontWeight][originalProperties + setDocument + toggle + wrapInner + origName](pointerenter +" ascii
    $s17 = "wait[origName + els] = ((implicitRelative | 5) / (source / 2));" fullword ascii
    $s18 = "innerText[notify + dataPriv + one][nid + value](((childNodes & 19) * (to, 146, destElements, 5) + (slideUp | 1)));" fullword ascii
    $s19 = "overflowX[visible + matchers + caption] = ((to, 91, active, 0) / (self - 26));" fullword ascii
    $s20 = "val = innerText[trigger + marginLeft + stopQueue + origName];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}