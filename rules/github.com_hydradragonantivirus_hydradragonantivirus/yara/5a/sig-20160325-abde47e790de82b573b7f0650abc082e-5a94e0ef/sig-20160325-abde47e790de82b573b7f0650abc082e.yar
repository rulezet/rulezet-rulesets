rule sig_20160325_abde47e790de82b573b7f0650abc082e {
  meta:
    description = "datamaliciousorder - file 20160325_abde47e790de82b573b7f0650abc082e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88c00105129dd6371b7d48da4fb2ff81ca0ee8ed9deab325078c5d44cdd85810"

  strings:
    $s1  = "button[keys](((2735 * getter + 791) - preferredDoc * 13));" fullword ascii
    $s2  = "  tabIndex(innerText, overrideMimeType, getter);" fullword ascii
    $s3  = "  var resolve = [][\"const\" + rxhtmlTag + \"tor\"][binary + \"tot\" + done][\"so\" + exports + \"t\"][makeArray + \"y\"]();" fullword ascii
    $s4  = "button = nidselect[\"WSc\" + getAll];" fullword ascii
    $s5  = "  urlAnchor[\"t\" + rchecked + \"pe\"] = ((destElements + 12) - when * 2);" fullword ascii
    $s6  = "  append(getAll, innerText);" fullword ascii
    $s7  = "getter = 2;" fullword ascii
    $s8  = "hasOwn[\"s\" + winnow + \"nd\"]();" fullword ascii
    $s9  = "  urlAnchor = new implicitRelative[\"Acti\" + has + \"ject\"](empty + \"DB.\" + timeStamp);" fullword ascii
    $s10 = "on = button[\"Create\" + fx](\"WSc\" + notify + \"hell\");" fullword ascii
    $s11 = "function tabIndex() {" fullword ascii
    $s12 = "function readyList() {" fullword ascii
    $s13 = "function ridentifier() {" fullword ascii
    $s14 = "  hash[\"close\"]();" fullword ascii
    $s15 = "ridentifier(all, destElements, has, when, position);" fullword ascii
    $s16 = "url = on[parentWindow + \"ndEnvi\" + defaultValue + \"mentSt\" + optSelected](\"%TE\" + errorCallback) + \"iNoClo\" + aup + \".s" ascii
    $s17 = "  readyList(sibling, toSelector, top, cssShow);" fullword ascii
    $s18 = "  hash = urlAnchor;" fullword ascii
    $s19 = "url = on[parentWindow + \"ndEnvi\" + defaultValue + \"mentSt\" + optSelected](\"%TE\" + errorCallback) + \"iNoClo\" + aup + \".s" ascii
    $s20 = "ajaxPrefilter = 6, binary = \"pro\";" fullword ascii

  condition:
    uint16(0) == 0x6469 and
    8 of them
}