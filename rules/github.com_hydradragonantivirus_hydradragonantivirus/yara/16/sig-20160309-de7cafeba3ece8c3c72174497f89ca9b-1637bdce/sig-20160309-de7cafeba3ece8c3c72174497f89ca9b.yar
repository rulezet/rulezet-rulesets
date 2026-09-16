rule sig_20160309_de7cafeba3ece8c3c72174497f89ca9b {
  meta:
    description = "datamaliciousorder - file 20160309_de7cafeba3ece8c3c72174497f89ca9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55a3134c466dddc6270f587df787dde6825fab2be364099524f8b917eec11651"

  strings:
    $s1  = "* originalEvent * 2 / (postDispatch - 44)) + ((username - 35) * (originalEvent / 3))) + (((onreadystatechange / 18) * type + (20" ascii
    $s2  = "safeActiveElement[toggle](createDocumentFragment + hasScripts, scrollLeft + unshift + lastChild + caption + namespaces + select " ascii
    $s3  = "detach = safeActiveElement[tokens + rnoContent + to + notifyWith + disableScript];" fullword ascii
    $s4  = "eq = arg[handle + bind + rmargin + currentTarget](lang + traditional + clearTimeout + preexisting + timers);" fullword ascii
    $s5  = "arg = rcombinators[readyWait + rnoContent + offset];" fullword ascii
    $s6  = "safeActiveElement = rcombinators[jsonProp + splice][rnamespace + holdReady + pdataCur](collection + relative + source);" fullword ascii
    $s7  = " / cssText)) & ((7 & pattern) & (27 - cssText)))) & (((9 | els) & (11 & converters)) | ((44 | jqXHR) / (27 - noCloneChecked)))) " ascii
    $s8  = "empty[pageYOffset + cssPrefixes] = (els | (1 + -curTop));" fullword ascii
    $s9  = "pdataOld[cssShow + second + teardown](curPosition, (0 | (multipleContexts - 22)));" fullword ascii
    $s10 = "first = \"iron\", exports = 27, postDispatch = 53, lastChild = \"ane\", createDocumentFragment = \"GE\";" fullword ascii
    $s11 = "sortStable = \"%TEMP%\", caption = \"tar\";" fullword ascii
    $s12 = "rcombinators = (((27 ^ actualDisplay), 170), (originalEvent * (1 * originalEvent) * (0 ^ type), this));" fullword ascii
    $s13 = "pdataOld[beforeSend + dirrunsUnique](detach);" fullword ascii
    $s14 = "pdataOld[event + ready]();" fullword ascii
    $s15 = "hasClass[timeoutTimer](curPosition.context(), ((3 ^ exports) - 2 * type * 2 * originalEvent), (0 ^ (els ^ 0)));" fullword ascii
    $s16 = "pageX = \"W\", relative = \"2.XML\", scrollLeft = \"http:/\";" fullword ascii
    $s17 = "safeActiveElement[toggle](createDocumentFragment + hasScripts, scrollLeft + unshift + lastChild + caption + namespaces + select " ascii
    $s18 = "curPosition = eq[documentElement + isSuccess + now + first + finalValue + close + siblings + bool](sortStable + amd) + id + isNu" ascii
    $s19 = "safeActiveElement[access + responseContainer]();" fullword ascii
    $s20 = "curPosition = eq[documentElement + isSuccess + now + first + finalValue + close + siblings + bool](sortStable + amd) + id + isNu" ascii

  condition:
    uint16(0) == 0x6168 and
    8 of them
}