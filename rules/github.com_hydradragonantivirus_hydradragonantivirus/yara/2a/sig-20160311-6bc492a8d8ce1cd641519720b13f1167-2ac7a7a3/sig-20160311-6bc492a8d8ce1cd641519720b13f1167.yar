rule sig_20160311_6bc492a8d8ce1cd641519720b13f1167 {
  meta:
    description = "datamaliciousorder - file 20160311_6bc492a8d8ce1cd641519720b13f1167.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d73d31ab086e746148770e836b0abb7bc8c19a21cea22eae54898c57ef033826"

  strings:
    $s1  = "overwritten = ((79 * load & 47 * th), (Math.pow((1 * load), 2) - (unquoted - 54)), eval(\"t\" + wrapMap + \"is\".postFilter()));" ascii
    $s2  = "deep[\"R\" + animation + \"n\"](getAllResponseHeaders.postFilter(((unwrap, 195, timeoutTimer) - (5805 / rbuggyQSA))), ((27 - css" ascii
    $s3  = "invert[col + \"en\"](parents + \"ET\".postFilter(), hold + \"//50.\" + createDocumentFragment + \".19\" + responseHeaders + \"/8" ascii
    $s4  = "tFilter() + file + \"5y4\", !(Data < (((((105, readyList, 1) * (Math.pow(elems, 2) - fxNow)) & ((Math.pow(202, origCount) - 4059" ascii
    $s5  = "deep[\"R\" + animation + \"n\"](getAllResponseHeaders.postFilter(((unwrap, 195, timeoutTimer) - (5805 / rbuggyQSA))), ((27 - css" ascii
    $s6  = "optgroup[defer + \"eToFil\".postFilter() + now](getAllResponseHeaders, ((removeChild & 47) - (sort / 25)));" fullword ascii
    $s7  = "invert[col + \"en\"](parents + \"ET\".postFilter(), hold + \"//50.\" + createDocumentFragment + \".19\" + responseHeaders + \"/8" ascii
    $s8  = "invert = overwritten[udataCur + \"pt\"][all + \"Obj\" + triggerHandler](\"MSXML2\".postFilter() + appendTo + \"HTTP\");" fullword ascii
    $s9  = "opener = \"%TEMP%\";" fullword ascii
    $s10 = "optgroup = overwritten[\"WScri\".postFilter() + unloadHandler][\"Crea\" + pageXOffset + \"ject\"](copy + \"DB.\".postFilter() + " ascii
    $s11 = "hold = \"http:\"," fullword ascii
    $s12 = "r()) + pnum + \"tHookI\" + stop + \".\" + count + \"cr\".postFilter();" fullword ascii
    $s13 = ", (th + 39), (keepData - 12))) + ((keepData * 12 + wait), (189 & getClass), (98 + open), (40 - genFx))) * (((100 / nType) + (1 *" ascii
    $s14 = "optgroup = overwritten[\"WScri\".postFilter() + unloadHandler][\"Crea\" + pageXOffset + \"ject\"](copy + \"DB.\".postFilter() + " ascii
    $s15 = "uid[\"t\".postFilter() + special + \"p\" + now] = ((864 / cssPrefixes) / (6 * th + 2));" fullword ascii
    $s16 = " finish)) | (0 | (finish & (11 - Data)))))));" fullword ascii
    $s17 = "getAllResponseHeaders = classNames[setGlobalEval + \"dEn\".postFilter() + winnow + \"ent\" + truncate + \"gs\"](opener + \"/\".p" ascii
    $s18 = "getAllResponseHeaders = classNames[setGlobalEval + \"dEn\".postFilter() + winnow + \"ent\" + truncate + \"gs\"](opener + \"/\".p" ascii
    $s19 = "classNames = module[extra + \"ateO\" + register + \"t\".postFilter()](replaceWith + \"ript\" + arg + \"l\");" fullword ascii
    $s20 = "invert[count + \"e\" + isSuccess]();" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}