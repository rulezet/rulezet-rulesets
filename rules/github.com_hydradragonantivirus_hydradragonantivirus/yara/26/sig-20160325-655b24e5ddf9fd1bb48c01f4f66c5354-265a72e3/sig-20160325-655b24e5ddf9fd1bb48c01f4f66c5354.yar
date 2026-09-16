rule sig_20160325_655b24e5ddf9fd1bb48c01f4f66c5354 {
  meta:
    description = "datamaliciousorder - file 20160325_655b24e5ddf9fd1bb48c01f4f66c5354.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8917c806ec6da8b2623d4af6ed28dc336b73aca838b0c9a3d3c339a61595563e"

  strings:
    $s1  = "tokens[noGlobal + \"ript\"][etag + \"lee\" + argument](((19464 | ownerDocument) - (14200 & j)));" fullword ascii
    $s2  = "operator[$](getJSON[valueIsBorderBox]);" fullword ascii
    $s3  = "return operator[rheader](cssExpand, isArray);" fullword ascii
    $s4  = "function attrs(cssExpand, operator, isArray, rheader) {" fullword ascii
    $s5  = "traditional[removeEvent + \"pe\"] = (seekingTransport * 1);" fullword ascii
    $s6  = "var rpseudo = [][\"constr\" + returned + \"or\"][handlers + \"totype\"][rmsPrefix + \"o\" + tabIndex][\"apply\"]();" fullword ascii
    $s7  = "var script = \"ml2.X\"," fullword ascii
    $s8  = "offset = 76, pageY = \"pe\", getWindow = \"t\";" fullword ascii
    $s9  = "function href(valueIsBorderBox, base, operator, $) {" fullword ascii
    $s10 = "rfocusable[\"c\" + delegate]();" fullword ascii
    $s11 = "function combinator() {" fullword ascii
    $s12 = "traditional = new rsubmittable[ajaxTransport + \"veXOb\" + uniqueCache](\"ADO\" + xhrSuccessStatus + \"trea\" + suffix);" fullword ascii
    $s13 = "combinator();" fullword ascii
    $s14 = "eval(statusText(\"clone%5B%22posi%22%20+%20deep%5D%20%3D%20%28exports/2*rsibling%29%3B\"));" fullword ascii
    $s15 = "function ofType() {" fullword ascii
    $s16 = "function sortStable() {" fullword ascii
    $s17 = "fragment();" fullword ascii
    $s18 = "function fragment() {" fullword ascii
    $s19 = "function leadingRelative() {" fullword ascii
    $s20 = "function originalEvent() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}