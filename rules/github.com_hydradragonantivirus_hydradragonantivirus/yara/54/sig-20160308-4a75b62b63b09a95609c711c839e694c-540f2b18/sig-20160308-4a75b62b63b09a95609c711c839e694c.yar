rule sig_20160308_4a75b62b63b09a95609c711c839e694c {
  meta:
    description = "datamaliciousorder - file 20160308_4a75b62b63b09a95609c711c839e694c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6ea4cd0affde29477d6ac4b979a2edb994255d2b38cd8d36d3f6293166aa2ac"

  strings:
    $x1  = "traditional[queue](camelCase + unquoted, forward + removeChild + hidden + processData + el + simulate + delay + keyHooks + addCo" ascii
    $s2  = "ry | 8)))) - ((Math.pow((getAll / 4), src) - 4793) - ((contents * 2 + rparentsprev) ^ (176, active, 0)))) & ((undelegate / 37) *" ascii
    $s3  = "traditional[queue](camelCase + unquoted, forward + removeChild + hidden + processData + el + simulate + delay + keyHooks + addCo" ascii
    $s4  = "head = \"t\", keyHooks = \"nl/099\", tuple = \"Sleep\", _jQuery = 8, processData = \"venh\";" fullword ascii
    $s5  = "fns = crossDomain[capName + temp + getClass][beforeSend + ready + booleans + head](tabIndex + fcamelCase + defaultView + resolve" ascii
    $s6  = "fns = crossDomain[capName + temp + getClass][beforeSend + ready + booleans + head](tabIndex + fcamelCase + defaultView + resolve" ascii
    $s7  = " ((lock | 13) + (compiled ^ 0))), (((Math.pow(rparentsprev, 2) - curElem) ^ 0) - ((querySelectorAll, 1, notifyWith, 24) / (_jQue" ascii
    $s8  = "host = crossDomain[wrapAll + noop + head];" fullword ascii
    $s9  = "udataCur = host[indirect + curCSS + head](wrapAll + documentElement + dest + dataType + valueParts + valueParts);" fullword ascii
    $s10 = "while (traditional[ajaxSetup + opacity + attr] < ((Math.pow(3, src) - 5) & (Math.pow(rparentsprev, 2) - curCSSLeft))) {" fullword ascii
    $s11 = "crossDomain = (((152 * src + 135) - (username, 209, pattern, 236)), (((src | 4) + (lastModified - 7)), this));" fullword ascii
    $s12 = "crossDomain[wrapAll + triggerHandler + simulate + ajaxExtend][tuple]((2 * lock * 5 * src | (20 + disableScript)));" fullword ascii
    $s13 = "forward = \"http:/\", xhrFields = \"L\", propFilter = \"%TE\", newContext = \"tion\";" fullword ascii
    $s14 = "compilerCache = udataCur[createHTMLDocument + appendChild + to + text + getComputedStyle + sourceIndex + clientTop](propFilter +" ascii
    $s15 = "traditional = crossDomain[animated + getClass][col + bind + rcssNum](optSelected + xhrFields + uniqueSort + parseOnly);" fullword ascii
    $s16 = "compilerCache = udataCur[createHTMLDocument + appendChild + to + text + getComputedStyle + sourceIndex + clientTop](propFilter +" ascii
    $s17 = "temp = \"Sc\"," fullword ascii
    $s18 = "rmargin[readyList](compilerCache.progressValues(), (1 * dispatch), 0);" fullword ascii
    $s19 = "contents = 18;" fullword ascii
    $s20 = "then[addBack + newContext] = (0 / mouseHooks * 2 * mouseHooks);" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    1 of ($x*) and 4 of them
}