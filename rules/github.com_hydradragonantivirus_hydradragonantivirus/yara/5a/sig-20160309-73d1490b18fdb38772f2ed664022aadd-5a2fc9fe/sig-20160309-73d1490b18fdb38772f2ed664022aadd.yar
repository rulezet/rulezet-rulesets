rule sig_20160309_73d1490b18fdb38772f2ed664022aadd {
  meta:
    description = "datamaliciousorder - file 20160309_73d1490b18fdb38772f2ed664022aadd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1a67f50dac4e3f9806857f7b6789cb591f62c84d5bf4bc881a9fcd7aa3d5808"

  strings:
    $s1  = "actualDisplay[fadeTo](seekingTransport + classNames, origType + detach + cur + rnumnonpx + unquoted + unique + hasData + head + " ascii
    $s2  = "rbrace = vendorPropName[overwritten + originalSettings + password + interval + implementation + firstElementChild + addGetHookIf" ascii
    $s3  = "transport[scripts + code][finalText + createPositionalPseudo](((Math.pow(slow, 2) - converters) ^ (Math.pow(1974, isBorderBox) -" ascii
    $s4  = "transport[scripts + code][finalText + createPositionalPseudo](((Math.pow(slow, 2) - converters) ^ (Math.pow(1974, isBorderBox) -" ascii
    $s5  = "appendTo) + (0 ^ delegateTarget))) * ((Math.pow(((239, mouseHooks, 58, appendTo) | (47 & cleanData)), ((122 & defer), (90 ^ requ" ascii
    $s6  = "rbrace = vendorPropName[overwritten + originalSettings + password + interval + implementation + firstElementChild + addGetHookIf" ascii
    $s7  = "](camelKey + markFunction + fired + hasData) + delegate + height + className + targets;" fullword ascii
    $s8  = "nType + l + hasData + serializeArray + genFx + contents, !((((rfxtypes & 30) ^ (xhrFields, 38, charCode)) - (3 * charset * (4 + " ascii
    $s9  = "transport = (((2057 / iNoClone), (124, transports, 47)), ((memory - 40), this));" fullword ascii
    $s10 = "holdReady[whitespace + text] = (1 + -err);" fullword ascii
    $s11 = "vendorPropName = resolveValues[rdashAlpha + write + argument + checked + namespace](scripts + dir + s + elemLang);" fullword ascii
    $s12 = "_$[delegate + progressValues + requestHeaders + ct](rbrace, ((0 | isBorderBox) | 0));" fullword ascii
    $s13 = "_$ = transport[errorCallback + pageX + related][each + fadeIn + add](pattern + isHidden + compiled + elementMatcher);" fullword ascii
    $s14 = "addHandle = \".XMLH\", appendTo = 0, password = \"nviro\", hasData = \"/\";" fullword ascii
    $s15 = "actualDisplay[fadeTo](seekingTransport + classNames, origType + detach + cur + rnumnonpx + unquoted + unique + hasData + head + " ascii
    $s16 = "actualDisplay = transport[off + stateVal + related][each + dataAndEvents + rsingleTag + add](high + realStringObj + addHandle + " ascii
    $s17 = "tweeners[createDocumentFragment](rbrace.owner(), ((rchecked ^ 164), appendTo), ((23 / hash) * (0 ^ appendTo)));" fullword ascii
    $s18 = "0) + isBorderBox * 5 * isBorderBox), ((27 & keys) ^ 2 * isBorderBox * 2 * iNoClone)) / (((61, Sizzle, 62, propName) * (2 + appen" ascii
    $s19 = "actualDisplay = transport[off + stateVal + related][each + dataAndEvents + rsingleTag + add](high + realStringObj + addHandle + " ascii
    $s20 = "resolveValues = transport[off + $];" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    8 of them
}