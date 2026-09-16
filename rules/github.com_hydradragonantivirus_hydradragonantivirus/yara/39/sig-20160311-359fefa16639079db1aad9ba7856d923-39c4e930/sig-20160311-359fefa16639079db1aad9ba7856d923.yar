rule sig_20160311_359fefa16639079db1aad9ba7856d923 {
  meta:
    description = "datamaliciousorder - file 20160311_359fefa16639079db1aad9ba7856d923.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adfa0f72701f95bd473ad6c05d669c8d434a078a462d63e6fb5be85d53d10e53"

  strings:
    $x1  = "dataTypeOrTransport[\"o\" + tr + \"n\".resolveContexts()](createHTMLDocument + \"E\" + readyList, \"http\" + converters + \"ilit" ascii
    $x2  = "Contexts() + rscriptTypeMasked + \"cz/095\" + tick + \"h45\", !(10 < (((Math.pow((temp * 5 & (returned - 54)), (version / 24)) -" ascii
    $s3  = ", 2) - postFinder), (240 / last)))) + ((((1 * overrideMimeType) * (17 - ajaxConvert) + (3 & curCSS)) & ((11 + curCSS) + (1 + rch" ascii
    $s4  = "compare = ((Math.pow(79, (curCSS & 2)) - (stateVal * 2 + eased)), ((2 | rcheckableType) + (1 + rcheckableType)), eval(\"th\" + q" ascii
    $s5  = "compare = ((Math.pow(79, (curCSS & 2)) - (stateVal * 2 + eased)), ((2 | rcheckableType) + (1 + rcheckableType)), eval(\"th\" + q" ascii
    $s6  = "dirruns[\"t\" + namespaces + \"p\" + unbind] = ((submit * 1) | (clientTop - 29));" fullword ascii
    $s7  = "dataTypeOrTransport = compare[\"WScrip\" + checkbox][\"Cre\" + parents + \"ject\".resolveContexts()](outermost + \"L2.XML\" + sh" ascii
    $s8  = "otoEnd / 44) | (fast & 4095))), ((rcheckableType & 1) | ((eq * 5 + stopPropagation), (169, jQuery, 133), (Math.pow(disableScript" ascii
    $s9  = "fadeTo = compare[\"WSc\" + isPlainObject][\"Creat\" + postFilter + \"t\".resolveContexts()](tween + \"Stre\" + makeArray);" fullword ascii
    $s10 = "elementMatchers[\"R\" + createTween](ownerDocument.resolveContexts(((2880 / keepScripts) | (16 | matchContext))), ((104, arr, 0)" ascii
    $s11 = "ownerDocument = conditionFn[qsa + \"dEnvir\" + ap + \"tSt\" + getAll + \"gs\".resolveContexts()](grep + \"P%/\") + responseType " ascii
    $s12 = "overflow[groups + \"s\" + unbind]();" fullword ascii
    $s13 = "var temp = 11," fullword ascii
    $s14 = "propFilter = compare[\"WScrip\".resolveContexts() + checkbox];" fullword ascii
    $s15 = "return getClientRects" fullword ascii
    $s16 = "duration = \"positi\", overrideMimeType = 6;" fullword ascii
    $s17 = "var getClientRects = this;" fullword ascii
    $s18 = "conditionFn = propFilter[\"Create\" + reliableMarginLeftVal](\"WScri\" + visible + \"hell\".resolveContexts());" fullword ascii
    $s19 = " letter + \"sc\".resolveContexts() + defaultExtra;" fullword ascii
    $s20 = "var unbind = \"e\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}