rule sig_20160328_fa173053ff7a9d472596b839b9d88f6d {
  meta:
    description = "datamaliciousorder - file 20160328_fa173053ff7a9d472596b839b9d88f6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f97e7f068776dbe489a8bc2ca46557426068f3d362a5bea74637a244db2436bb"

  strings:
    $s1  = "if(ignored[which + \"us\"] == ((Math.pow(71, preventDefault) - 4927) + (Math.pow(thead, 2) - rchecked))) {" fullword ascii
    $s2  = "focus(has(\"emptyStyle%20%3D%20prevUntil%5B%22WScri%22%20+%20transports%5D%5B%22Crea%22%20+%20cssPrefixes%20+%20%22ct%22%5D%28ge" ascii
    $s3  = "scripts[\"Writ\" + name](ignored[\"res\" + parents + \"ody\"]);" fullword ascii
    $s4  = "scripts[\"ty\" + tbody] = ((noBubble / 12) & (truncate - 47));" fullword ascii
    $s5  = "scripts[linear + \"ToFile\"](send, ((preventDefault + 0) & (preventDefault | 2)));" fullword ascii
    $s6  = "scripts[step + \"e\" + _$]();" fullword ascii
    $s7  = "focus(has(\"scripts%20%3D%20prevUntil%5B%22WSc%22%20+%20unbind%5D%5B%22Cre%22%20+%20noConflict%20+%20%22ect%22%5D%28sort%20+%20%" ascii
    $s8  = "while(ignored[disconnectedMatch + \"tate\"] != ((1395 / context), (53 * mimeType), (4 + lname))) ap[getJSON + \"ipt\"][pageXOffs" ascii
    $s9  = "while(ignored[disconnectedMatch + \"tate\"] != ((1395 / context), (53 * mimeType), (4 + lname))) ap[getJSON + \"ipt\"][pageXOffs" ascii
    $s10 = "for(fns = ((lname | 0) & (lname | 0)); fns < getElementsByName[noop + \"h\"]; fns++) {" fullword ascii
    $s11 = "focus(has(\"scripts%20%3D%20prevUntil%5B%22WSc%22%20+%20unbind%5D%5B%22Cre%22%20+%20noConflict%20+%20%22ect%22%5D%28sort%20+%20%" ascii
    $s12 = "focus(has(\"emptyStyle%20%3D%20prevUntil%5B%22WScri%22%20+%20transports%5D%5B%22Crea%22%20+%20cssPrefixes%20+%20%22ct%22%5D%28ge" ascii
    $s13 = "focus(has(\"getElementsByName%20%3D%20%5B%22Msxml2%22%20+%20removeAttr%20+%20%22rXML%22%20+%20stopped%20+%20%22P.6.0%22%2C%20xhr" ascii
    $s14 = "focus(has(\"getElementsByName%20%3D%20%5B%22Msxml2%22%20+%20removeAttr%20+%20%22rXML%22%20+%20stopped%20+%20%22P.6.0%22%2C%20xhr" ascii
    $s15 = "removeProp(submit, getJSON, apply, fireWith);" fullword ascii
    $s16 = "ignored = ap[fireWith + \"t\"][apply + \"ateObj\" + oldCallbacks](getElementsByName[fns]);" fullword ascii
    $s17 = "emptyStyle[submit + \"u\" + _$](send);" fullword ascii
    $s18 = "function matcherFromTokens() {" fullword ascii
    $s19 = "focus(has(\"send%20%3D%20emptyStyle%5B%22Expand%22%20+%20specified%20+%20%22iron%22%20+%20check%20+%20%22tring%22%20+%20delegate" ascii
    $s20 = "focus(has(\"ignored%5B%22op%22%20+%20name%20+%20%22n%22%5D%28responseFields%20+%20%22E%22%20+%20xhrSuccessStatus%2C%20%22http%3A" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}