rule sig_20160309_3a6a99726288b42c5f5aa5134e687c07 {
  meta:
    description = "datamaliciousorder - file 20160309_3a6a99726288b42c5f5aa5134e687c07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e12961641ff05e1e706a1805077642abce05da15226013e60917354d8c4f477f"

  strings:
    $x1  = "pixelPositionVal[queue](fn + serialize, body + nodeNameSelector + firstElementChild + rpseudo + unwrap + curCSSTop + cur + rkeyE" ascii
    $s2  = "getWidthOrHeight[contents + css + getAttributeNode + configurable](host, ((38 + eventHandle) - (656 / code)));" fullword ascii
    $s3  = "host = sortOrder[getWindow + toggleClass + defaultPrevented + createTextNode + holdReady + useCache + originalEvent + createTwee" ascii
    $s4  = "n + preventDefault + getStyles + scripts + elemdisplay + prefilterOrFactory](constructor + Data + readyWait) + params + scriptCh" ascii
    $s5  = "vent + safeActiveElement + targets + rfocusMorph, !((((((31 & leadingRelative) & (21 ^ siblingCheck)) / ((14 + dataType) | (Math" ascii
    $s6  = "reliableMarginRight[defaultPrefilter](host.once(), ((19 & leadingRelative) - (7 ^ what)), 0);" fullword ascii
    $s7  = "host = sortOrder[getWindow + toggleClass + defaultPrevented + createTextNode + holdReady + useCache + originalEvent + createTwee" ascii
    $s8  = "time[unmatched + scripts + attachEvent][compare](((5805 ^ rcheckableType) + (8881 & expanded)));" fullword ascii
    $s9  = "pixelPositionVal[queue](fn + serialize, body + nodeNameSelector + firstElementChild + rpseudo + unwrap + curCSSTop + cur + rkeyE" ascii
    $s10 = "getWidthOrHeight = time[unmatched + originalEvent + response][split + getStyles + rcssNum + clearInterval](superMatcher + nType " ascii
    $s11 = "time = ((201 | getClientRects), ((17 * getElementsByTagName * 5 / (src * 3 + ifModified)), this));" fullword ascii
    $s12 = "pixelPositionVal = time[letter + context + response][split + bulk + throws + allTypes](isHidden + get + timeoutTimer + pdataCur)" ascii
    $s13 = "pixelPositionVal = time[letter + context + response][split + bulk + throws + allTypes](isHidden + get + timeoutTimer + pdataCur)" ascii
    $s14 = "getWidthOrHeight = time[unmatched + originalEvent + response][split + getStyles + rcssNum + clearInterval](superMatcher + nType " ascii
    $s15 = "locked[conditionFn + includeWidth + rtypenamespace + curCSS] = ((0 ^ completeDeferred) | (0 | completeDeferred));" fullword ascii
    $s16 = "getWidthOrHeight[queue]();" fullword ascii
    $s17 = "contents = \"sav\";" fullword ascii
    $s18 = "padding = getWidthOrHeight;" fullword ascii
    $s19 = "    body = \"http:\"," fullword ascii
    $s20 = "isTrigger = time[letter + image];" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    1 of ($x*) and 4 of them
}