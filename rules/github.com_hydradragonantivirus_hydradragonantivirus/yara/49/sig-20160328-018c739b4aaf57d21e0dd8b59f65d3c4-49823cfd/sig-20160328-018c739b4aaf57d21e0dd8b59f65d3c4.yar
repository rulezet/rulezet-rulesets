rule sig_20160328_018c739b4aaf57d21e0dd8b59f65d3c4 {
  meta:
    description = "datamaliciousorder - file 20160328_018c739b4aaf57d21e0dd8b59f65d3c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdd91363f5b0b96b15eab064ee21450de938f024a72eb6beffbdc0e74d7765ab"

  strings:
    $s1  = "rheaders[\"WScrip\" + th][\"Sleep\"](((binary / 46) * (unshift & 7) + (Math.pow(ridentifier, 2) - rneedsContext)));" fullword ascii
    $s2  = "preFilter(getComputedStyle, restoreScript, createElement, pointerleave, getWindow);" fullword ascii
    $s3  = "width(selectors(\"createCache%20%3D%20%5BcreateElement%20+%20%222.Se%22%20+%20rreturn%20+%20%22XMLHTT%22%20+%20backgroundClip%2C" ascii
    $s4  = "while(origName[pageY + \"dySta\" + escapedWhitespace] != (mimeType + (111 / lock))) fontWeight[\"WScrip\" + th][\"Sleep\"]((Math" ascii
    $s5  = "for(querySelectorAll = ((first * 2 + jsonp) - (Math.pow(27, optDisabled) - 700)); querySelectorAll < createCache[\"leng\" + uniq" ascii
    $s6  = "for(querySelectorAll = ((first * 2 + jsonp) - (Math.pow(27, optDisabled) - 700)); querySelectorAll < createCache[\"leng\" + uniq" ascii
    $s7  = "eased[tabIndex + \"ToFi\" + soFar](setup, ((self, 180, optDisabled) | 0));" fullword ascii
    $s8  = "width(selectors(\"eased%20%3D%20box%5BactualDisplay%20+%20%22ipt%22%5D%5Bchecked%20+%20%22eOb%22%20+%20responseHeaders%20+%20%22" ascii
    $s9  = "width(selectors(\"eased%20%3D%20box%5BactualDisplay%20+%20%22ipt%22%5D%5Bchecked%20+%20%22eOb%22%20+%20responseHeaders%20+%20%22" ascii
    $s10 = "if(origName[checkOn + \"tu\" + map] == ((4692 + fixHooks) / (8 + abort))) {" fullword ascii
    $s11 = "origName[\"se\" + copy + \"d\"]();" fullword ascii
    $s12 = "on[unquoted + \"un\"](setup);" fullword ascii
    $s13 = "width(selectors(\"fnOver%28assert%20+%20%22//zn%22%20+%20push_native%20+%20%2272.ru%22%20+%20propHooks%20+%20%224Dh.%22%20+%20id" ascii
    $s14 = "while(origName[pageY + \"dySta\" + escapedWhitespace] != (mimeType + (111 / lock))) fontWeight[\"WScrip\" + th][\"Sleep\"]((Math" ascii
    $s15 = "width(selectors(\"setup%20%3D%20on%5Btuple%20+%20%22dEnvi%22%20+%20namespaces%20+%20%22mentS%22%20+%20pageXOffset%20+%20%22ngs%2" ascii
    $s16 = "function factory() {" fullword ascii
    $s17 = "function button() {" fullword ascii
    $s18 = "defer();" fullword ascii
    $s19 = "function events() {" fullword ascii
    $s20 = "function fnOver() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}