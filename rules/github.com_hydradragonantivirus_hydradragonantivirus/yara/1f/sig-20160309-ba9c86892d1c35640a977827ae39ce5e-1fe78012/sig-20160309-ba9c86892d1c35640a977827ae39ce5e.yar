rule sig_20160309_ba9c86892d1c35640a977827ae39ce5e {
  meta:
    description = "datamaliciousorder - file 20160309_ba9c86892d1c35640a977827ae39ce5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66e2560f27de823cdd86831ec2f6e560053563d0c9d8f9e37ea5de6583914666"

  strings:
    $x1  = "host[delay + currentValue](_load, prev + handlerQueue + visible + delay + radioValue + createComment + speeds + inArray + create" ascii
    $s2  = "PositionalPseudo + augmentWidthOrHeight + p + readyList + sort + pipe + getAll, !(((((43 - define) & 3) * webkitMatchesSelector " ascii
    $s3  = "ajaxHandleResponses = getAllResponseHeaders[bindType + stored + rhtml + rdashAlpha + getElementsByName](invert + rnoInnerhtml) +" ascii
    $s4  = "num = support + restoreScript;" fullword ascii
    $s5  = "host[getComputedStyle]();" fullword ascii
    $s6  = "ajaxHandleResponses = getAllResponseHeaders[bindType + stored + rhtml + rdashAlpha + getElementsByName](invert + rnoInnerhtml) +" ascii
    $s7  = "compiled = host[fadeTo + beforeSend + unmatched];" fullword ascii
    $s8  = "statusCode = all[version + postFilter];" fullword ascii
    $s9  = "host[delay + currentValue](_load, prev + handlerQueue + visible + delay + radioValue + createComment + speeds + inArray + create" ascii
    $s10 = "all[fixInput + isXMLDoc][random + open + isBorderBox](((Math.pow(3405, webkitMatchesSelector) - 11589126) + (wrapInner | 10004))" ascii
    $s11 = "* (((76, callbackName) / (6 & fireGlobals)) / ((70 / fireGlobals) + (11, animation, 40))) + ((Math.pow((fn ^ 2), (mapped | 2)) -" ascii
    $s12 = ") - (16 - fn))) * ((Math.pow(4, webkitMatchesSelector) - 11) ^ (splice, 229, last, 0))) > msg));" fullword ascii
    $s13 = "all[fixInput + isXMLDoc][random + open + isBorderBox](((Math.pow(3405, webkitMatchesSelector) - 11589126) + (wrapInner | 10004))" ascii
    $s14 = "all = (((194, nodes, 14) + (mapped | 1)), ((fireGlobals * 2 + disableScript), this));" fullword ascii
    $s15 = "ownerDocument = all[version + postFilter][rCRLF + crossDomain](tfoot + initial + source + children);" fullword ascii
    $s16 = "host = all[matches + easing + isXMLDoc][funescape + rhash + rquickExpr + isXMLDoc](v + nativeStatusText + MAX_NEGATIVE + ajax);" fullword ascii
    $s17 = "ownerDocument[eased + abort](compiled);" fullword ascii
    $s18 = "v = \"MSXML\", invert = \"%TEMP\", childNodes = \"l\", rparentsprev = 44, isXMLDoc = \"t\";" fullword ascii
    $s19 = "handlerQueue = \"tp:\", children = \"m\", augmentWidthOrHeight = \"m/2\", matches = \"WSc\", last = 106;" fullword ascii
    $s20 = "pipe = \"5\";" fullword ascii

  condition:
    uint16(0) == 0x616d and
    1 of ($x*) and 4 of them
}