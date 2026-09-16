rule sig_20160329_73f458f3b935774a30f4a8494be42235 {
  meta:
    description = "datamaliciousorder - file 20160329_73f458f3b935774a30f4a8494be42235.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "332b51cc4b8f3987b5a8b33ef5bf51cab71cf654b75b805c8dfc21f01ccbe0c6"

  strings:
    $s1  = "rcleanScript[\"t\" + responseHeadersString + \"e\"] = (1 * resolve);" fullword ascii
    $s2  = "version(\"rcleanScript%20%3D%20readyState%5BincludeWidth%20+%20%22rip%22%20+%20condense%5D%5B%22Creat%22%20+%20expanded%20+%20%2" ascii
    $s3  = "version(\"rcleanScript%20%3D%20readyState%5BincludeWidth%20+%20%22rip%22%20+%20condense%5D%5B%22Creat%22%20+%20expanded%20+%20%2" ascii
    $s4  = "after = rscriptTypeMasked[elemData + \"ipt\"][remove + \"eObjec\" + condense](_default[iterator]);" fullword ascii
    $s5  = "rcleanScript[ownerDocument + \"o\" + success] = ((17 / globalEval) * (3 | resolve));" fullword ascii
    $s6  = "rcleanScript[linear + \"te\"](after[divStyle + \"seBody\"]);" fullword ascii
    $s7  = "version(\"letter%20%3D%20rscriptTypeMasked%5B%22WSc%22%20+%20clazz%5D%5B%22Cre%22%20+%20test%20+%20%22bjec%22%20+%20condense%5D%" ascii
    $s8  = "function getElementsByClassName(structure, tokenCache, host) {" fullword ascii
    $s9  = "version(\"letter%20%3D%20rscriptTypeMasked%5B%22WSc%22%20+%20clazz%5D%5B%22Cre%22%20+%20test%20+%20%22bjec%22%20+%20condense%5D%" ascii
    $s10 = "function version(requestHeaders) {" fullword ascii
    $s11 = "version(\"_default%20%3D%20%5B%22Msxm%22%20+%20pixelPositionVal%20+%20%22Server%22%20+%20animation%20+%20%22P.6.0%22%2C%20PI%20+" ascii
    $s12 = "after[\"se\" + isArrayLike + \"d\"]();" fullword ascii
    $s13 = "if(after[\"statu\" + split] == ((92 & refElements) + (112 | allTypes))) {" fullword ascii
    $s14 = "letter[\"Ru\" + isArrayLike](originalProperties);" fullword ascii
    $s15 = "token(resolve, ownerDocument, refElements, defineProperty, elemData);" fullword ascii
    $s16 = "version(\"originalProperties%20%3D%20letter%5Bround%20+%20%22Env%22%20+%20owner%20+%20%22mentS%22%20+%20pattern%20+%20%22ngs%22%" ascii
    $s17 = "onerror(opener, elems, whitespace, pdataOld, linear);" fullword ascii
    $s18 = "function onerror(buildParams, noCloneChecked) {" fullword ascii
    $s19 = "version(\"while%20%28after%5Bwhich%20+%20%22tate%22%5D%20%21%3D%20%28%284%7CcheckNonElements%29%29%29%20etag%5BstopOnFalse%20+%2" ascii
    $s20 = "version(\"originalProperties%20%3D%20letter%5Bround%20+%20%22Env%22%20+%20owner%20+%20%22mentS%22%20+%20pattern%20+%20%22ngs%22%" ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}