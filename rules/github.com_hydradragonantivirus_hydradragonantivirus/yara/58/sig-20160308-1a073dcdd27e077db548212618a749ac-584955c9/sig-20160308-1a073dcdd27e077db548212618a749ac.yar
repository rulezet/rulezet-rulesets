rule sig_20160308_1a073dcdd27e077db548212618a749ac {
  meta:
    description = "datamaliciousorder - file 20160308_1a073dcdd27e077db548212618a749ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c3b518710387cc3b5cdefe3bf977fcafa88b9603ea844ccb88aaf3564ee2cf5"

  strings:
    $s1  = "getById[detach + matcherOut](letter + closest, trigger + ap + isXML + mouseHooks + specified + originalSettings + proxy + set, !" ascii
    $s2  = "(6 < ((Math.pow((((completed | 35), (identifier / 11)) | (fireWith * 2 * fireWith * 2 * fireWith * 2 - values * 3 * fireWith * 3" ascii
    $s3  = "getById = func[pipe + fadeIn + old + bySet][createElement + Deferred + head + cssFn + position + optall](emptyStyle + _default +" ascii
    $s4  = "func = (((2 | time) | (6762 / headers)), (((34 - handler) + (180, clearTimeout)), this));" fullword ascii
    $s5  = "rtrim[parentNode](getById[on + computeStyleTests + flag]);" fullword ascii
    $s6  = "getById[detach + matcherOut](letter + closest, trigger + ap + isXML + mouseHooks + specified + originalSettings + proxy + set, !" ascii
    $s7  = "getById = func[pipe + fadeIn + old + bySet][createElement + Deferred + head + cssFn + position + optall](emptyStyle + _default +" ascii
    $s8  = "rtrim = func[rfocusMorph + disableScript][hide + addBack + bySet](dispatch + marginLeft + fire + unloadHandler);" fullword ascii
    $s9  = "  func[rfocusMorph + disableScript][factory + linear](((values * 2) * (classNames ^ 31) + (prop, 15, support)));" fullword ascii
    $s10 = "func[currentValue + clearCloneStyle + pattern + bySet][documentIsHTML + fnOver](((14488 | preventDefault) & (9503 ^ getElementsB" ascii
    $s11 = "pageY[offsetParent + guid] = ((wait + -1) | (setTimeout / 28));" fullword ascii
    $s12 = "  pipe = \"WS\"," fullword ascii
    $s13 = "disableScript = \"pt\", append = \"E\", set = \"65gh5\", selected = \"he\", parentNode = \"write\";" fullword ascii
    $s14 = "head = \"eateOb\";" fullword ascii
    $s15 = "while (getById[returnValue + caption] < ((196 / width) | 4)) {" fullword ascii
    $s16 = "func[currentValue + clearCloneStyle + pattern + bySet][documentIsHTML + fnOver](((14488 | preventDefault) & (9503 ^ getElementsB" ascii
    $s17 = "first = func[vendorPropName + bySet];" fullword ascii
    $s18 = "dataTypeExpression[split](collection.preDispatch(), ((divStyle, 214, setTimeout) / 5 * fireWith), (1 & setTimeout));" fullword ascii
    $s19 = "bling + Deferred;" fullword ascii
    $s20 = "split = rnamespace + matcherFromGroupMatchers;" fullword ascii

  condition:
    uint16(0) == 0x6c6f and
    8 of them
}