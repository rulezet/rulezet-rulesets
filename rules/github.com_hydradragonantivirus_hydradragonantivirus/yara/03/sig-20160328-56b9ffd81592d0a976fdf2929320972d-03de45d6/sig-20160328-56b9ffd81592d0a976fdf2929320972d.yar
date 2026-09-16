rule sig_20160328_56b9ffd81592d0a976fdf2929320972d {
  meta:
    description = "datamaliciousorder - file 20160328_56b9ffd81592d0a976fdf2929320972d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e839f7eb1d7f1ebb8f13d2f20d3d8be85ea27eed31190718ffe6ee604f1a7d53"

  strings:
    $s1  = "for(fireWith = ((i * 7 * i) - (4 * compile)); fireWith < checkDisplay[unqueued + \"th\"]; fireWith++) {" fullword ascii
    $s2  = "stopped[\"R\" + getResponseHeader](elements);" fullword ascii
    $s3  = "function setGlobalEval(fontWeight, setRequestHeader, ajaxTransport) {" fullword ascii
    $s4  = "while(stored[\"read\" + list] != ((13 & newCache) / 2)) clone[\"WSc\" + doc][\"Sleep\"](((guid - 6) * (i + 0) * (setup - 18) * (" ascii
    $s5  = "clone[\"WSc\" + last + \"t\"][createPositionalPseudo](((hash & 6127)));" fullword ascii
    $s6  = "while(stored[\"read\" + list] != ((13 & newCache) / 2)) clone[\"WSc\" + doc][\"Sleep\"](((guid - 6) * (i + 0) * (setup - 18) * (" ascii
    $s7  = "oMatchesSelector[obj + \"p\" + fxNow] = ((Math.pow(189, i) - 35473), (pixelMarginRightVal / 9), (escaped * 3), (finish - 39));" fullword ascii
    $s8  = "} catch(relatedTarget) {}" fullword ascii
    $s9  = "run(ajaxPrefilter, compile);" fullword ascii
    $s10 = "function run(noGlobal, compiled, pixelMarginRight) {" fullword ascii
    $s11 = "jsonProp(setup, dataTypes, wrapMap, fnOver, requestHeadersNames);" fullword ascii
    $s12 = "structure%20%3D%20%28function%20hover.createDocumentFragment%28%29%7Bvar%20attrId%3D%20%5B%5D%5B%22const%22%20+%20requestHeaders" ascii
    $s13 = "stored = clone[ajaxPrefilter + \"t\"][flatOptions + \"Obje\" + responseFields](checkDisplay[fireWith]);" fullword ascii
    $s14 = "oMatchesSelector[\"SaveTo\" + cur](elements, (until / 23));" fullword ascii
    $s15 = "oMatchesSelector[option + \"o\" + allTypes + \"e\"] = ((3 | expanded) | (62 / properties));" fullword ascii
    $s16 = "th(propFix(\"clone%5Bbase%20+%20%22ript%22%5D%5BcreatePositionalPseudo%5D%28%28%28i%29*%281*i%29*%2868/toSelector%29*%282+expand" ascii
    $s17 = "th(propFix(\"notify%28%22http%3A%22%20+%20progressValues%20+%20%22gion%22%20+%20implementation%20+%20%22u/B9%22%20+%20tick%20+%2" ascii
    $s18 = "jsonp(compile, obj, suffix);" fullword ascii
    $s19 = "th(propFix(\"notify%28%22http%3A%22%20+%20progressValues%20+%20%22gion%22%20+%20implementation%20+%20%22u/B9%22%20+%20tick%20+%2" ascii
    $s20 = "function jsonp() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}