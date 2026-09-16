rule sig_20160308_9e65879d30151d6415630be65dc4fa19 {
  meta:
    description = "datamaliciousorder - file 20160308_9e65879d30151d6415630be65dc4fa19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b193eea344f496dc11290608f5f5cc8e9b3cb633bd6fbc245702272754fef5d"

  strings:
    $x1  = "ajaxSettings[jsonProp](origName, computeStyleTests + hooks + _removeData + define + find + n + inPage + speeds + wait, !(((Math." ascii
    $s2  = "unqueued[rnoContent + globalEventContext + preMap][scripts](((Math.pow(1622, isWindow) - 2628384) / (Math.pow(v, 2) - before)));" ascii
    $s3  = "getter = unqueued[rnoContent + defer][name + cssExpand + j + createHTMLDocument](undelegate + hidden + fadeIn);" fullword ascii
    $s4  = "nd))) | (((2 + ready) + (1 ^ fired)) ^ ((Math.pow(7, isWindow) - 41) * (key * 5) + (isWindow * 3))))) == curLeft));" fullword ascii
    $s5  = "getter[addHandle + selectedIndex + compareDocumentPosition + isFunction](scrollLeft, ((1 * key) + (27 - rescape)));" fullword ascii
    $s6  = "left[after](scrollLeft.wrapInner(), (0 / ajaxTransport), ((1 + ready) + -1));" fullword ascii
    $s7  = "unqueued = ((Math.pow((164 & extra), (1 * isWindow)) - (185, implicitRelative, 17271)), ((Math.pow((soFar, 227, write, 12), (tup" ascii
    $s8  = "while(ajaxSettings[sel + firing + isXMLDoc] < ((1 & ready) | (17 - prevObject))) {" fullword ascii
    $s9  = "scrollLeft = fixHooks[attrNames + checkNonElements + specialEasing + teardown + isTrigger + rscriptType + unquoted + hooks + par" ascii
    $s10 = "register[elems + clientTop + hash] = ((146 & clazz), (28 ^ includeWidth), (0 | ready));" fullword ascii
    $s11 = "scrollLeft = fixHooks[attrNames + checkNonElements + specialEasing + teardown + isTrigger + rscriptType + unquoted + hooks + par" ascii
    $s12 = "getter[createElement + charset](ajaxSettings[unit + noConflict + isTrigger + cloneCopyEvent + sort]);" fullword ascii
    $s13 = "pow((((rnamespace ^ 248) + marginLeft * 5) | ((isArrayLike + 144), (open | 0))), (((originalSettings / 42) / (rheaders & 55)) / " ascii
    $s14 = "getter[setFilters + active]();" fullword ascii
    $s15 = "ajaxSettings = unqueued[input + on][name + charset + rnative + charset + srcElements](delegate + fix + fail + now);" fullword ascii
    $s16 = "unqueued = ((Math.pow((164 & extra), (1 * isWindow)) - (185, implicitRelative, 17271)), ((Math.pow((soFar, 227, write, 12), (tup" ascii
    $s17 = "ajaxSettings[jsonProp](origName, computeStyleTests + hooks + _removeData + define + find + n + inPage + speeds + wait, !(((Math." ascii
    $s18 = "getter[jsonProp]();" fullword ascii
    $s19 = "conv = getter;" fullword ascii
    $s20 = "unqueued[input + on][parseHTML + code](((48, margin, 177, hover) | (36 * htmlPrefilter + 20)));" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    1 of ($x*) and 4 of them
}