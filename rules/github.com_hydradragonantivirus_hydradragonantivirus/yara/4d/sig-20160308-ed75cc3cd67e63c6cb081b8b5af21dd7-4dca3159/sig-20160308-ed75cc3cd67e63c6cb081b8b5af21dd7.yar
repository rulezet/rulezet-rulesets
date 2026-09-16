rule sig_20160308_ed75cc3cd67e63c6cb081b8b5af21dd7 {
  meta:
    description = "datamaliciousorder - file 20160308_ed75cc3cd67e63c6cb081b8b5af21dd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "509245952b9eac6a0b68b11aabe904812a6468920e01b52dc4e86e8ae38b264d"

  strings:
    $s1  = "getBoundingClientRect = preMap[pageYOffset + serializeArray][pdataOld + bup + ajax + map](createPseudo + script + l + markFuncti" ascii
    $s2  = "getBoundingClientRect = preMap[pageYOffset + serializeArray][pdataOld + bup + ajax + map](createPseudo + script + l + markFuncti" ascii
    $s3  = "preMap = (((0 | prev) + (30 ^ replaceWith)), (((36, getStyles, 27) - (rfocusable)), this));" fullword ascii
    $s4  = "getBoundingClientRect[tbody + ajax + remove + ajax](elemData, ((1 * excess) & (2 & hash)));" fullword ascii
    $s5  = "veValues) | (1 * excess))) | ((34 / unwrap) * (1 ^ hash) * (3 + test) - ((73, _data, 128, unwrap) - (0 | cssShow)))) * (((215 ^ " ascii
    $s6  = "var backgroundClip = \"%TEMP%\";" fullword ascii
    $s7  = "while (sel[rjsonp + multipleContexts + dirruns + ajax] < ((286 - rxhtmlTag), 2 * progress, (5120 / opt), 2 * excess)) {" fullword ascii
    $s8  = "trim[access + adjustCSS + mozMatchesSelector + crossDomain] = ((172 - rcomma), (24 ^ cssText), (1 & test));" fullword ascii
    $s9  = "elemData = step[createDocumentFragment + nodeName + el + done + elementMatcher](backgroundClip + stopped) + nid + nidselect + di" ascii
    $s10 = "sel[firing](valueIsBorderBox, camelCase + stopped + nid + mouseenter + attachEvent + nid + raw + dequeue + htmlPrefilter + match" ascii
    $s11 = "preMap[DOMParser + getById][simulate](((0 | opt) | (100 & preventDefault)));" fullword ascii
    $s12 = "sel = preMap[origFn + load][ret + getById + attr + rclickable + map](chainable + marginDiv + position + global);" fullword ascii
    $s13 = "step = clientY[parentWindow + attr + iNoClone + overflowX](checkbox + responseHeaders + propHooks);" fullword ascii
    $s14 = "preMap[origFn + load][simulate](((15756 - valHooks) & (5130 | insertAfter)));" fullword ascii
    $s15 = "originalSettings), 2) + test) + ((2 * (old ^ 3) * (old * 3) * filter / (55 / returned) * 3) - (((finish ^ 31) | (newSelector ^ 9" ascii
    $s16 = "ed + selector + wrapMap, !(9 < (((((excess ^ 101), (opt * 3 + matches), (144 - newSelector), (28 / activeElement)) + ((0 / resol" ascii
    $s17 = "1)), ((n, 77, rneedsContext) + 3 * unwrap), (Math.pow((7038 / tweener), (1 + old)) - (41407 - callback)), ((35 ^ fast) - (20 | r" ascii
    $s18 = "clientY = preMap[document + hasCompare + serializeArray];" fullword ascii
    $s19 = "matched = \"7j\", dirruns = \"ystat\", matches = 19, rcomma = 90, fast = 21, access = \"p\";" fullword ascii
    $s20 = "script = \"ODB\";" fullword ascii

  condition:
    uint16(0) == 0x7277 and
    8 of them
}