rule sig_20160328_aa155a0ea3bc8505f903da977a0ff708 {
  meta:
    description = "datamaliciousorder - file 20160328_aa155a0ea3bc8505f903da977a0ff708.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c95bf419a5d25c34af7e18f551f42e828939092e9e80ac3fac3e22e75db4493"

  strings:
    $x1  = "while (propFilter[processData + \"ySta\" + createHTMLDocument] != ((getComputedStyle + 27) / (implementation - 18))) addCombinat" ascii
    $x2  = "while (propFilter[processData + \"ySta\" + createHTMLDocument] != ((getComputedStyle + 27) / (implementation - 18))) addCombinat" ascii
    $s3  = "matchIndexes[\"SaveT\" + wait](contentType, ((defaultView + 0) - (rtypenamespace + 0)));" fullword ascii
    $s4  = "firstChild[protocol + \"un\"](contentType);" fullword ascii
    $s5  = "suffix = step = rhtml = addCombinator = hasContent.async();" fullword ascii
    $s6  = "function src(getById, dataAndEvents) {" fullword ascii
    $s7  = "ap(adjusted(\"hidden%20%3D%20%5Btick%20+%20%22l2.Se%22%20+%20input%20+%20%22XML%22%20+%20rwhitespace%20+%20%22.6.0%22%2C%20clien" ascii
    $s8  = "for (removeAttr = ((27, cssProps, 188, matchesSelector) | (0 | matchesSelector)); removeAttr < hidden[\"le\" + inspected + \"t\"" ascii
    $s9  = "matchIndexes[focusin + \"p\" + reset]();" fullword ascii
    $s10 = "matchIndexes[\"Write\"](propFilter[indirect + \"nseB\" + state]);" fullword ascii
    $s11 = "for (removeAttr = ((27, cssProps, 188, matchesSelector) | (0 | matchesSelector)); removeAttr < hidden[\"le\" + inspected + \"t\"" ascii
    $s12 = "if (propFilter[\"s\" + linear + \"s\"] == ((2 + matchesSelector) * (5 | lastChild) * (5 & curOffset) * (2 & elem) * 2)) {" fullword ascii
    $s13 = "function mappedTypes() {" fullword ascii
    $s14 = "propFilter = step[\"WScrip\" + rescape][\"Crea\" + cors + \"ject\"](hidden[removeAttr]);" fullword ascii
    $s15 = "function s(hasData, elements) {" fullword ascii
    $s16 = "function rnamespace(rsubmittable) {" fullword ascii
    $s17 = "function adjusted(href) {" fullword ascii
    $s18 = "src(preferredDoc, fireGlobals, reject, scrollTop, linear);" fullword ascii
    $s19 = "function allTypes(rfocusable, optionSet) {" fullword ascii
    $s20 = "show(progress, tr, dataTypes);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}