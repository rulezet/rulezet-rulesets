rule sig_20160313_404b54b7d58750bfa4593b86d418267c {
  meta:
    description = "datamaliciousorder - file 20160313_404b54b7d58750bfa4593b86d418267c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "165f53a3f60ae45455557adf2135981f63f24052990016dc8624c4d8adfb2c3c"

  strings:
    $x1  = "isXMLDoc[round + \"pe\" + eventPath](\"GE\" + msMatchesSelector, \"http:\" + scale + \"lloguy\" + condense + \"/70\" + using + " ascii
    $s2  = "relatedTarget[\"t\" + childNodes + \"p\" + rtypenamespace] = ((Math.pow(cache, 2) - conv2), (26 * file + 10), (file * 36 + outer" ascii
    $s3  = "relatedTarget[\"t\" + childNodes + \"p\" + rtypenamespace] = ((Math.pow(cache, 2) - conv2), (26 * file + 10), (file * 36 + outer" ascii
    $s4  = "isXMLDoc[round + \"pe\" + eventPath](\"GE\" + msMatchesSelector, \"http:\" + scale + \"lloguy\" + condense + \"/70\" + using + " ascii
    $s5  = "pattern = 1072, condense = \"ff.com\", beforeSend = \"cr\", tween = 4;" fullword ascii
    $s6  = "offset[\"Ru\" + eventPath](fn, (6 - file), (0 & mappedTypes));" fullword ascii
    $s7  = "lang[round + \"p\" + dirrunsUnique]();" fullword ascii
    $s8  = "before * 3, (outerCache & 3)) - (wrapInner, 36571565))), (((percent, 194), (evt | 1)) / ((Math.pow(tween, 2) - fcamelCase) * (37" ascii
    $s9  = "h.pow(((((1225 & send) | (1065 | pattern)) / ((Math.pow(21, outerCache) - 415) + (mappedTypes + 4))), (Math.pow((_default / 31)," ascii
    $s10 = "re)) - 13 * merge * 7) - ((ajaxPrefilter & 63) - (outerCache + 19))) * ((triggerHandler / 38) & expanded))) > 3));" fullword ascii
    $s11 = "lang = this[visible + \"ipt\"][owner + \"Obje\" + reset](\"ADO\" + display + \"tream\");" fullword ascii
    $s12 = "lang[dispatch + \"eToFil\" + rtypenamespace](fn, ((23 | oldCallbacks) - (21 & bup)));" fullword ascii
    $s13 = "isXMLDoc = this[\"WScr\" + fired][\"Create\" + cssText + \"t\"](size + \"2.X\" + attrs + \"TP\");" fullword ascii
    $s14 = "visible = \"WScr\";" fullword ascii
    $s15 = "expanded = 5;" fullword ascii
    $s16 = "function matches() {" fullword ascii
    $s17 = "function elem() {" fullword ascii
    $s18 = "function easing() {" fullword ascii
    $s19 = "easing();" fullword ascii
    $s20 = "function position() {" fullword ascii

  condition:
    uint16(0) == 0x7277 and
    1 of ($x*) and 4 of them
}