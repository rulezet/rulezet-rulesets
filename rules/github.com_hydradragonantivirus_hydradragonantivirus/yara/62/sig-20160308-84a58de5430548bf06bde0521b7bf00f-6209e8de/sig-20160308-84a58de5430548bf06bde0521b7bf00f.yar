rule sig_20160308_84a58de5430548bf06bde0521b7bf00f {
  meta:
    description = "datamaliciousorder - file 20160308_84a58de5430548bf06bde0521b7bf00f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67bb749e2adbfbcaed59a0702373f90e1f0a00221d6caca459201a4a3df93400"

  strings:
    $s1  = "defer[prop + opt + collection](visible, ((Math.pow(dataFilter, 2) - keepScripts) / (1 * matchIndexes)));" fullword ascii
    $s2  = "elementMatchers[hide](origFn, errorCallback + conv2 + detectDuplicates + finish + rxhtmlTag + notify + nodeValue + set + s + clo" ascii
    $s3  = "visible = valueIsBorderBox[removeEvent + copy + fadeIn + idx + preFilters + slow + fixHook](width + _evalUrl) + getElementsByNam" ascii
    $s4  = "elementMatchers = defaultPrefilter[rjsonp + pushStack + scrollTop + prefilterOrFactory][createElement + createTextNode + seeking" ascii
    $s5  = "Transport + duplicates](responseType + write + rxhtmlTag + ridentifier + rscriptType);" fullword ascii
    $s6  = "lang = \"p\", dataFilter = 21, width = \"%TEMP%\", hide = \"open\", conv2 = \"tp://\";" fullword ascii
    $s7  = "  defaultPrefilter[rsibling + preDispatch][slideToggle + collection + lang](((elemdisplay ^ 84) + (Math.pow(iNoClone, 2) - domMa" ascii
    $s8  = "  defaultPrefilter[rsibling + preDispatch][slideToggle + collection + lang](((elemdisplay ^ 84) + (Math.pow(iNoClone, 2) - domMa" ascii
    $s9  = "while (elementMatchers[qualifier + responseFields] < (Math.pow((options ^ 3), (orig ^ 3)) - (orig + 4))) {" fullword ascii
    $s10 = "getWidthOrHeight = \"d\", _evalUrl = \"/\", prefilterOrFactory = \"ript\", contents = \"rite\", num = \"reateO\";" fullword ascii
    $s11 = "visible = valueIsBorderBox[removeEvent + copy + fadeIn + idx + preFilters + slow + fixHook](width + _evalUrl) + getElementsByNam" ascii
    $s12 = "elementMatchers[result + getWidthOrHeight]();" fullword ascii
    $s13 = "defaultPrefilter[rjsonp + next + rtrim][unquoted](((265 * clientX + 169) - (resolveContexts ^ 4349)));" fullword ascii
    $s14 = "defer = defaultPrefilter[rpseudo + prefilterOrFactory][types + num + once + disable + tabIndex](filter + pushStack + sel + curOf" ascii
    $s15 = "e + mapped + isSimulated + transports + collection + rxhtmlTag + startLength;" fullword ascii
    $s16 = "defer = defaultPrefilter[rpseudo + prefilterOrFactory][types + num + once + disable + tabIndex](filter + pushStack + sel + curOf" ascii
    $s17 = "defaultPrefilter = (((55 ^ pixelPosition) * (0 ^ exports) + (6 + createPositionalPseudo)), (((15 & matchIndexes) & 11), this));" fullword ascii
    $s18 = "valueIsBorderBox = trim[rbrace + ifModified + tabIndex](outermostContext + tabIndex + preexisting + remaining);" fullword ascii
    $s19 = "defer[rclass + contents](elementMatchers[amd + tick + isXML + docElem]);" fullword ascii
    $s20 = "defer[isArray + idx]();" fullword ascii

  condition:
    uint16(0) == 0x4e69 and
    8 of them
}