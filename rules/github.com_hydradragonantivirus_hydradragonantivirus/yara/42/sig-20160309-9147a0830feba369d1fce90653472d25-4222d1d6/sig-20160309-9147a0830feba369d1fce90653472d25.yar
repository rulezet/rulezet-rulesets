rule sig_20160309_9147a0830feba369d1fce90653472d25 {
  meta:
    description = "datamaliciousorder - file 20160309_9147a0830feba369d1fce90653472d25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "583d23b017cc919a85a9e269fd7f746b9b1a692dc0021080022aef7584167f96"

  strings:
    $s1  = "cos[toggleClass + preFilter](divStyle, wrap + lastModified + global + origFn + defaultPrefilter + errorCallback + checked + noCo" ascii
    $s2  = "implementation = createPositionalPseudo[version + getText + nid + writable](completeDeferred + toSelector + pseudos + i);" fullword ascii
    $s3  = "first = (((6600 | currentTarget) / (31 + stopImmediatePropagation)), (((54 / stopImmediatePropagation) * (13 - escaped) + (5 - a" ascii
    $s4  = "first = (((6600 | currentTarget) / (31 + stopImmediatePropagation)), (((54 / stopImmediatePropagation) * (13 - escaped) + (5 - a" ascii
    $s5  = "checkDisplay[parts + options + pipe] = ((html / 39) ^ (unshift + -1));" fullword ascii
    $s6  = "cos = first[fnOut + cacheURL][namespaces + rcombinators + activeElement + requestHeaders](dirrunsUnique + defaultExtra + clientX" ascii
    $s7  = "cos = first[fnOut + cacheURL][namespaces + rcombinators + activeElement + requestHeaders](dirrunsUnique + defaultExtra + clientX" ascii
    $s8  = ") & ((((preMap / 28) * (image) + (1 + html)) & ((160 | clazz) / (127 - progress))) / (((69, binary, 1407) / (unshift | 21)) - ((" ascii
    $s9  = "checked = \"ys\", currentTarget = 3348, resolve = \"dy\";" fullword ascii
    $s10 = "msMatchesSelector[script + refElements]();" fullword ascii
    $s11 = "types[b + curCSS](thead, ((unshift * 0) | (apply, 228, handlers)));" fullword ascii
    $s12 = "urlAnchor = cos[overrideMimeType + overflow + propHooks + resolve];" fullword ascii
    $s13 = "first[fnOut + hookFn + ap][tabIndex](((9015 ^ getElementsByClassName) / (391 / param)));" fullword ascii
    $s14 = "thead = implementation[attrNames + callbackName + len + compare + reject + handlerQueue](rchecked + slideToggle) + tbody + retur" ascii
    $s15 = "thead = implementation[attrNames + callbackName + len + compare + reject + handlerQueue](rchecked + slideToggle) + tbody + retur" ascii
    $s16 = "cos[key + pseudo + eased]();" fullword ascii
    $s17 = "pipe = \"n\";" fullword ascii
    $s18 = "script = \"clos\";" fullword ascii
    $s19 = "nflict + curOffset + locked + related + qsa, !(2 < ((((option / 12) & ((wrapAll ^ 237), (async | 3))) | (((isEmptyObject | 5), d" ascii
    $s20 = "types[result + refElements](urlAnchor);" fullword ascii

  condition:
    uint16(0) == 0x7371 and
    8 of them
}