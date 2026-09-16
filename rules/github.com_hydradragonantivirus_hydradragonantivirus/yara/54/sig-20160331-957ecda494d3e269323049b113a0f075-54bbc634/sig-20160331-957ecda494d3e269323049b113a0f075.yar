rule sig_20160331_957ecda494d3e269323049b113a0f075 {
  meta:
    description = "datamaliciousorder - file 20160331_957ecda494d3e269323049b113a0f075.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa39690f19248fa2000a691c9f7c655345f7f14cd9a6083e9e9bb0b7bb12c867"

  strings:
    $s1  = "eval((854, unescape([\"var&nodeValue&%3D&%28%22Obje%22%29%2C&hookFn&%3D&%28%22xe%22%29%2C&setGlobalEval&%3D\", \"&%28%22cr%22%29" ascii
    $s2  = "attrHooks(\"while&%28which%5B%22readyS%22&+&setFilters%5D&%21%3D&%28%284+nativeStatusText%29%7C%2829-children%29%29%29&isSuccess" ascii
    $s3  = "which = manipulationTarget[delegateType + \"pt\"][tuples + \"Objec\" + handler](simulate[requestHeaders]);" fullword ascii
    $s4  = "visibility = manipulationTarget = dataTypeOrTransport = td = setOffset.globalEval();" fullword ascii
    $s5  = "postSelector[\"Sav\" + show + \"File\"](unshift, (1 * (delegateCount - 7)));" fullword ascii
    $s6  = "5B%22Sle%22&+&compile%5D%28%28%28100%7CcreatePositionalPseudo%29%26%28125%26currentTarget%29%29%29%3B\".replace(/&/g, '%20'));" fullword ascii
    $s7  = "if (which[\"st\" + reset + \"us\"] == ((206, root) * (2 | nativeStatusText) * (2 * root + 1) * (prefilterOrFactory - 0) * root))" ascii
    $s8  = "t%22%5D%5BcurCSSTop%5D%28%29%3B&return%2\", \"0disabled%3B%7D%2C&%22hell%22%29%2C&currentTarget&%3D&%28125%29%2C&rbuggyQSA&%3D&%" ascii
    $s9  = "isSuccess[check](((createCache * 25 + getPropertyValue) | (445 - err)));" fullword ascii
    $s10 = "for (requestHeaders = ((rjsonp / 38) * (nativeStatusText / 43)); requestHeaders < simulate[\"len\" + toggle + \"th\"]; requestHe" ascii
    $s11 = "for (requestHeaders = ((rjsonp / 38) * (nativeStatusText / 43)); requestHeaders < simulate[\"len\" + toggle + \"th\"]; requestHe" ascii
    $s12 = "postSelector[\"ty\" + rfocusable + \"e\"] = (apply | 1);" fullword ascii
    $s13 = "&%28%22http%3A%22%29%2C&createPositionalPseudo&%3D&%\", \"28100%29%2C&prefilterOrFactory&%3D&%285%29%2C&content&%3D&%28%22ml2.Se" ascii
    $s14 = "attrHooks(\"simulate&%3D&%5B%22Msx%22&+&content&+&%22rve%22&+&fnOver&+&%22TP.6%22&+&classNames%2C&%22Msxm%22&+&self&+&%22MLH%22&" ascii
    $s15 = "attrHooks(\"which%5B%22op%22&+&_queueHooks%5D%28%22GE%22&+&trim%2C&%22htt%22&+&rxhtmlTag&+&%22sicla%22&+&specified&+&%22munis.%2" ascii
    $s16 = "%28%22HTTP%22%29%3Bvar\", \"&handler&%3D&%28%22t%22%29%3Brhash&%3D&%28%22nmen%22%29%3B&show&%3D&%28%22eTo%22%29%\", \"3B&rreturn" ascii
    $s17 = "815%29%2C&overwritten&%3D&%28%22erXML%22%29%2C&pre\", \"vObject&%3D&%28%22unis.%22%29%2C&root&%3D&%282%29%3Bvar&compile&%3D&%28%" ascii
    $s18 = "postSelector[classes + \"en\"]();" fullword ascii
    $s19 = "which[\"se\" + fns]();" fullword ascii
    $s20 = "match[\"R\" + inspect](unshift);" fullword ascii

  condition:
    uint16(0) == 0x6f64 and
    8 of them
}