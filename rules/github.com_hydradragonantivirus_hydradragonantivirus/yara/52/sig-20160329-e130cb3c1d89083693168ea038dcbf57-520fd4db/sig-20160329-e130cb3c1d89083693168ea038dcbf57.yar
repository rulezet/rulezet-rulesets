rule sig_20160329_e130cb3c1d89083693168ea038dcbf57 {
  meta:
    description = "datamaliciousorder - file 20160329_e130cb3c1d89083693168ea038dcbf57.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a14236abc85a28866a01edc48ab25505f9eca4f24da287368ac08bb7f04a7798"

  strings:
    $s1  = "propFilter(\"resolve%20%3D%20scripts%5B%22WScrip%22%20+%20originalSettings%5D%5B%22Create%22%20+%20createComment%20+%20%22ct%22%" ascii
    $s2  = "function get(overrideMimeType) {" fullword ascii
    $s3  = "propFilter(\"resolve%20%3D%20scripts%5B%22WScrip%22%20+%20originalSettings%5D%5B%22Create%22%20+%20createComment%20+%20%22ct%22%" ascii
    $s4  = "complete = parsed = next = scripts = status.offsetHeight();" fullword ascii
    $s5  = "for(global = ((stopImmediatePropagation + -1)); global < related[undelegate + \"th\"]; global++) {" fullword ascii
    $s6  = "if(curCSS[\"statu\" + setup] == ((destElements / 47) + (Math.pow(returnFalse, 2) - rCRLF))) {" fullword ascii
    $s7  = "get(wrapAll, responseHeaders, trim, tfoot);" fullword ascii
    $s8  = "propFilter(\"owner%20%3D%20next%5BaugmentWidthOrHeight%20+%20%22ipt%22%5D%5BgetBoundingClientRect%20+%20%22eObj%22%20+%20clientT" ascii
    $s9  = "propFilter(\"owner%20%3D%20next%5BaugmentWidthOrHeight%20+%20%22ipt%22%5D%5BgetBoundingClientRect%20+%20%22eObj%22%20+%20clientT" ascii
    $s10 = "function returned(outermost, headers) {" fullword ascii
    $s11 = "owner[\"ty\" + prevUntil + \"e\"] = (1 | (trim | 0));" fullword ascii
    $s12 = "owner[\"op\" + propFix + \"n\"]();" fullword ascii
    $s13 = "owner[elems](curCSS[\"respo\" + send + \"y\"]);" fullword ascii
    $s14 = "owner[split + \"oFi\" + delegateType](hooks, ((stopImmediatePropagation | 0) * (timeoutTimer / 16)));" fullword ascii
    $s15 = "function username() {" fullword ascii
    $s16 = "function bind() {" fullword ascii
    $s17 = "parseFromString(trim, rwhitespace, responseType, createComment, timeoutTimer);" fullword ascii
    $s18 = "bind(split, duration);" fullword ascii
    $s19 = "propFilter(\"while%20%28curCSS%5Bmouseenter%20+%20%22yStat%22%20+%20propFix%5D%20%21%3D%20%28%28Math.pow%285%2C%20collection%29-" ascii
    $s20 = "propFilter(\"complete%5B%22WSc%22%20+%20splice%5D%5B%22Slee%22%20+%20prevUntil%5D%28%28%28swing%2C4864%29%7C%28disable*30+collec" ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}