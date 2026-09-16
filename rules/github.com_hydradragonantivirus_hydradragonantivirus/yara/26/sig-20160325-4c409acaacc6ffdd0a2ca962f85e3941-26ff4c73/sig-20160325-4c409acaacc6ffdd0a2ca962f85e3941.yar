rule sig_20160325_4c409acaacc6ffdd0a2ca962f85e3941 {
  meta:
    description = "datamaliciousorder - file 20160325_4c409acaacc6ffdd0a2ca962f85e3941.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a3688aa109a9d1f8c9844c20d7bee77727e8d7929a8644a8d719ce3c9019365"

  strings:
    $s1  = "  var getWidthOrHeight = [][\"const\" + matchedCount + \"or\"][content + \"totyp\" + unwrap][\"s\" + rneedsContext + \"t\"][subt" ascii
    $s2  = "  var getWidthOrHeight = [][\"const\" + matchedCount + \"or\"][content + \"totyp\" + unwrap][\"s\" + rneedsContext + \"t\"][subt" ascii
    $s3  = "  round[\"ty\" + oldfire] = ((fixInput & 1) | (inspected - 32));" fullword ascii
    $s4  = "dirruns = (function slideToggle.scrollTop() {" fullword ascii
    $s5  = "removeEventListener = rclickable[condense + \"Envi\" + dirruns + \"tSt\" + hasClass + \"s\"](matchContext + \"P%/\") + href + \"" ascii
    $s6  = "removeEventListener = rclickable[condense + \"Envi\" + dirruns + \"tSt\" + hasClass + \"s\"](matchContext + \"P%/\") + href + \"" ascii
    $s7  = "  return getWidthOrHeight;" fullword ascii
    $s8  = "content = \"pro\", cssProps = \"en\", unwrap = \"e\", expanded = \"op\";" fullword ascii
    $s9  = "  noConflict[body + \"s\" + unwrap]();" fullword ascii
    $s10 = "propHooks[defer + \"le\" + Sizzle]((788 + (response | 4116)));" fullword ascii
    $s11 = "propHooks = selected[\"WSc\" + overflowX];" fullword ascii
    $s12 = "  round = new selected[\"Active\" + replaceAll + \"ect\"](dataAndEvents + \".Strea\" + noop);" fullword ascii
    $s13 = "rclickable = propHooks[\"Creat\" + nextUntil + \"t\"](excess + \"rip\" + handler + \"hell\");" fullword ascii
    $s14 = "elem = propFix = selected = funcName = slideToggle.scrollTop();" fullword ascii
    $s15 = "  overflow(defaultExtra, matchedCount, keyCode, interval, response);" fullword ascii
    $s16 = "  return key[dataTypeOrTransport](src, checkbox);" fullword ascii
    $s17 = "function what(src, key, checkbox, dataTypeOrTransport) {" fullword ascii
    $s18 = "  eval(removeAttribute(\"what%28removeEventListener%2C%20round%2C%20%28%28arg*2+blur%29/19*blur%29%2C%20clazz%20+%20%22Fil%22%20" ascii
    $s19 = "function attrs(globalEval, eventPath, key, th) {" fullword ascii
    $s20 = "  eval(removeAttribute(\"what%28removeEventListener%2C%20round%2C%20%28%28arg*2+blur%29/19*blur%29%2C%20clazz%20+%20%22Fil%22%20" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}