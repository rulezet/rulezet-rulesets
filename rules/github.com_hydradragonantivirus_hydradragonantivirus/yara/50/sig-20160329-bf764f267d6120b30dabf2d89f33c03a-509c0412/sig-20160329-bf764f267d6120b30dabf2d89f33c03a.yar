rule sig_20160329_bf764f267d6120b30dabf2d89f33c03a {
  meta:
    description = "datamaliciousorder - file 20160329_bf764f267d6120b30dabf2d89f33c03a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28050a85c97d4ce381847412c65905a4bce4ca821b96f4c4cf08f3cef2701324"

  strings:
    $s1  = "button[handler + \"pt\"][slideToggle]((Math.pow((1552 + setOffset), (1 + defaultPrevented)) - (Math.pow(13258564, window) - 1757" ascii
    $s2  = "button[handler + \"pt\"][slideToggle]((Math.pow((1552 + setOffset), (1 + defaultPrevented)) - (Math.pow(13258564, window) - 1757" ascii
    $s3  = "if(excess[fixInput + \"us\"] == ((382 & createDocumentFragment) - (2 * blur))) {" fullword ascii
    $s4  = "function password(timers) {" fullword ascii
    $s5  = "version[\"Ru\" + ontype](originalEvent);" fullword ascii
    $s6  = "preexisting(\"version%20%3D%20completed%5B%22WScri%22%20+%20prependTo%5D%5B%22Creat%22%20+%20replaceAll%20+%20%22ject%22%5D%28ac" ascii
    $s7  = "preexisting(\"version%20%3D%20completed%5B%22WScri%22%20+%20prependTo%5D%5B%22Creat%22%20+%20replaceAll%20+%20%22ject%22%5D%28ac" ascii
    $s8  = "function postSelector() {" fullword ascii
    $s9  = "doneName(beforeunload, get, rparentsprev, blur);" fullword ascii
    $s10 = "password(tr, documentElement, createDocumentFragment, curOffset, tokenCache);" fullword ascii
    $s11 = "defaultValue[len + \"od\" + camelCase] = ((950 / load) - (63 & beforeunload));" fullword ascii
    $s12 = "defaultValue[code + \"en\"]();" fullword ascii
    $s13 = "preexisting(\"excess%5B%22op%22%20+%20camelCase%20+%20%22n%22%5D%28dataAndEvents%20+%20%22T%22%2C%20computed%20+%20%22%3A//l%22%" ascii
    $s14 = "excess[\"se\" + ontype + \"d\"]();" fullword ascii
    $s15 = "excess = nextSibling[handler + \"pt\"][unbind + \"Objec\" + rparentsprev](rescape[eq]);" fullword ascii
    $s16 = "function url(webkitMatchesSelector, sel, readyList) {" fullword ascii
    $s17 = "preexisting(\"button%5Bposition%20+%20%22rip%22%20+%20rparentsprev%5D%5B%22Sl%22%20+%20tweeners%5D%28%28%2865%2Csetter%2C2%29*%2" ascii
    $s18 = "defaultValue[\"t\" + tokenCache + \"e\"] = (1 * (container, 142, dataAttr, 1));" fullword ascii
    $s19 = "function computeStyleTests(expand, camelKey) {" fullword ascii
    $s20 = "function etag() {" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}