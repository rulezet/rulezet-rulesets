rule sig_20160311_418fed09d68448d0dde4b6ef5af8e5bb {
  meta:
    description = "datamaliciousorder - file 20160311_418fed09d68448d0dde4b6ef5af8e5bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3939c27a0038d372bbd53f0615392ffbd68c445fe31e9a72b12d5d97ec31ddc2"

  strings:
    $s1  = "dir[\"op\".emptyStyle() + truncate + \"n\"](markFunction + \"T\", speed + \"//pete\".emptyStyle() + responseContainer + \"em.co" ascii
    $s2  = "Left + \"45g\", !(old == (((((18 - updateFunc) + 0) + -(appendChild + 0)) | (((appendChild) * 2 * hasContent) & (15 & (winnow - " ascii
    $s3  = ")))) + (((Math.pow(setDocument, 2) - buildFragment) - (132 / rtagName)) & (((82 - list) / (352 / jsonp)))))));" fullword ascii
    $s4  = "winnow = 54, key = \"%TEMP\", when = \"Obj\";" fullword ascii
    $s5  = "hookFn = sibling[timer + \"andE\" + cloneCopyEvent + \"mentS\".emptyStyle() + deep + \"s\"](key + \"%/\") + on + \"ht\".emptySty" ascii
    $s6  = "hookFn = sibling[timer + \"andE\" + cloneCopyEvent + \"mentS\".emptyStyle() + deep + \"s\"](key + \"%/\") + on + \"ht\".emptySty" ascii
    $s7  = "getClass = stopPropagation[selectors + \"ript\"][view + \"ateObj\" + ret](\"ADODB\".emptyStyle() + rtypenamespace + \"eam\");" fullword ascii
    $s8  = "getElementsByName[response]();" fullword ascii
    $s9  = "hasContent = 5, ct = 13, pseudos = \"Res\", node = \"ipt\", unloadHandler = \"se\";" fullword ascii
    $s10 = "pImmediatePropagation + \"sc\" + reject;" fullword ascii
    $s11 = "    speed = \"http:\"," fullword ascii
    $s12 = "fire * 5 * xhr * 2)), (elems / (8 * responseFields)), (2 * oldfire * 2 * oldfire * 2 * oldfire, 192, (clearInterval | 69), elems" ascii
    $s13 = "dir = stopPropagation[\"WSc\" + preferredDoc][\"Create\".emptyStyle() + when + \"ect\"](stop + \".XM\" + progressValues);" fullword ascii
    $s14 = "dir[\"op\".emptyStyle() + truncate + \"n\"](markFunction + \"T\", speed + \"//pete\".emptyStyle() + responseContainer + \"em.co" ascii
    $s15 = "fn[calculatePosition + \"yp\".emptyStyle() + truncate] = 1;" fullword ascii
    $s16 = "completed = sibling;" fullword ascii
    $s17 = "function vendorPropName() {" fullword ascii
    $s18 = "        return responseHeaders" fullword ascii
    $s19 = "var view = (function String.prototype.emptyStyle() {" fullword ascii
    $s20 = "sibling = camel[tfoot + \"teObj\" + ret](\"WScrip\".emptyStyle() + nodeType + \"l\");" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}