rule sig_20160313_8ca05df4a33b1151f2fdb6890173cca8 {
  meta:
    description = "datamaliciousorder - file 20160313_8ca05df4a33b1151f2fdb6890173cca8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbb451e420ec6f33fc4e669b1183093bd03b3b7014238b89af7808343760575f"

  strings:
    $s1  = "cloneNode[unit + \"e\" + trim](\"GE\" + requestHeadersNames, \"http\" + callbackName + \"hel\" + offset + \"f.c\" + factory + \"" ascii
    $s2  = "cloneNode[unit + \"e\" + trim](\"GE\" + requestHeadersNames, \"http\" + callbackName + \"hel\" + offset + \"f.c\" + factory + \"" ascii
    $s3  = " (disconnectedMatch | 0)) + ((disconnectedMatch | 6) + (pseudo + -1)))))));" fullword ascii
    $s4  = "144 / optDisabled) & 3) + ((Math.pow(camel * 2, camel) - (8 + pseudo)))) == (((2 * oMatchesSelector) | (1 * ((Math.pow(after, 2)" ascii
    $s5  = "cloneNode = this[parts + \"ript\"][xhrSuccessStatus + \"Obje\" + rxhtmlTag](\"MSXM\" + setMatched + \"HTTP\");" fullword ascii
    $s6  = " - abort) / (149, queue, 94, attaches)))) & ((((177 & concat), (Math.pow(3, camel) - 4)) * ((curCSSLeft & 3) + pattern)) | ((2 +" ascii
    $s7  = "vendorPropName = this[conv + \"pt\"][unique + \"eOb\" + tabIndex](\"ADODB.\" + now + \"m\");" fullword ascii
    $s8  = "compilerCache[\"Ru\" + trim](contains, ((pseudo + 0) + -(hover, 103, elemLang, 1)), ((rcomma, 57, pattern) | 0));" fullword ascii
    $s9  = "host = \"eTo\";" fullword ascii
    $s10 = "vendorPropName[\"sav\" + host + \"File\"](contains, ((1 * camel) & (3 & curCSSLeft)));" fullword ascii
    $s11 = "xml = \"se\", offset = \"loguyf\";" fullword ascii
    $s12 = "swap = this[\"WScrip\" + matchAnyContext];" fullword ascii
    $s13 = "vendorPropName[selection + \"pe\" + trim]();" fullword ascii
    $s14 = "nodeIndex[\"t\" + curLeft + \"e\"] = (pseudo * 1);" fullword ascii
    $s15 = "rcssNum = swap[\"Cre\" + diff + \"bjec\" + matchAnyContext](\"WScr\" + fns + \"hell\");" fullword ascii
    $s16 = "curLeft = \"yp\", rcomma = 122, pattern = 0, optDisabled = 48;" fullword ascii
    $s17 = "contains = rcssNum[outermostContext + \"ndEnv\" + cacheLength + \"nmentS\" + oldfire](\"%TE\" + resolve) + \"runesc\" + siblings" ascii
    $s18 = "contains = rcssNum[outermostContext + \"ndEnv\" + cacheLength + \"nmentS\" + oldfire](\"%TE\" + resolve) + \"runesc\" + siblings" ascii
    $s19 = "eventDoc = (function createButtonPseudo.getClass() {" fullword ascii
    $s20 = "selection = \"o\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}