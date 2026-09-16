rule sig_20160329_2a9e18fc8ce1905e68ea9d691882e4af {
  meta:
    description = "datamaliciousorder - file 20160329_2a9e18fc8ce1905e68ea9d691882e4af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d820a2027564656e8e5c10ae563aedb68e9dccb260d3d009986b3e776a44622"

  strings:
    $s1  = "if (getClientRects[errorCallback + \"us\"] == ((headers + 48) * (m / 41) + (bool - 34))) {" fullword ascii
    $s2  = "size[display + \"ipt\"][htmlPrefilter](((Math.pow(3204, stateString) - 10261607) + (selectors | 155)));" fullword ascii
    $s3  = "msFullscreenElement(\"while%20%28getClientRects%5B%22readyS%22%20+%20statusText%5D%20%21%3D%20%28%28matched%7C0%29%7C%28stateStr" ascii
    $s4  = "getClientRects[padding + \"n\" + reject]();" fullword ascii
    $s5  = "msFullscreenElement(\"while%20%28getClientRects%5B%22readyS%22%20+%20statusText%5D%20%21%3D%20%28%28matched%7C0%29%7C%28stateStr" ascii
    $s6  = "getStyles(innerHTML, htmlPrefilter, _load, fragment);" fullword ascii
    $s7  = "function msFullscreenElement(getElementById) {" fullword ascii
    $s8  = "function getStyles(button) {" fullword ascii
    $s9  = "elemData[pseudos + \"p\" + each] = replaceWith;" fullword ascii
    $s10 = "msFullscreenElement(\"initial%5B%22WSc%22%20+%20option%20+%20%22t%22%5D%5BhtmlPrefilter%5D%28%28Math.pow%28%28ajaxExtend*2+first" ascii
    $s11 = "elemData[complete + \"e\" + callback]();" fullword ascii
    $s12 = "function ready(isXMLDoc, props) {" fullword ascii
    $s13 = "msFullscreenElement(\"initial%5B%22WSc%22%20+%20option%20+%20%22t%22%5D%5BhtmlPrefilter%5D%28%28Math.pow%28%28ajaxExtend*2+first" ascii
    $s14 = "ready(errorCallback, rfocusMorph);" fullword ascii
    $s15 = "return implicitRelative(unescape(getElementById));" fullword ascii
    $s16 = "function cos(rhtml) {" fullword ascii
    $s17 = "querySelectorAll(simulate, innerHTML, href);" fullword ascii
    $s18 = "function querySelectorAll(cors, rsibling, elementMatcher) {" fullword ascii
    $s19 = "function msMatchesSelector(defineProperty, shift) {" fullword ascii
    $s20 = "hookFn(serialize, matcher, click, bool);" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}