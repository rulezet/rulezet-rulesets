rule sig_20160329_4c5102612c6055a4bee6759b9229477e {
  meta:
    description = "datamaliciousorder - file 20160329_4c5102612c6055a4bee6759b9229477e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32f79df961690e2a1c78066a7fd86071a47434461d5e8355a736c7aa06ddeb23"

  strings:
    $s1  = "modified[fnOver + \"pt\"][Sizzle + \"lee\" + password](((computeStyleTests - 903) & (define / 7)));" fullword ascii
    $s2  = "binary(\"types%5B%22W%22%20+%20target%20+%20%22e%22%5D%28unshift%5BvendorPropName%20+%20%22ons%22%20+%20map%20+%20%22y%22%5D%29%" ascii
    $s3  = "binary(\"types%5B%22W%22%20+%20target%20+%20%22e%22%5D%28unshift%5BvendorPropName%20+%20%22ons%22%20+%20map%20+%20%22y%22%5D%29%" ascii
    $s4  = "structure[\"WScrip\" + idx][\"Slee\" + password](((removeChild, 23, createTextNode, 8077) & (html + 4330)));" fullword ascii
    $s5  = "types[\"SaveTo\" + fail](valueIsBorderBox, ((completed | 0) | (removeChild * 2)));" fullword ascii
    $s6  = "MAX_NEGATIVE(target, markFunction, context);" fullword ascii
    $s7  = "unshift = structure[\"WSc\" + matcherFromGroupMatchers][\"Create\" + until + \"t\"](firing[getAttributeNode]);" fullword ascii
    $s8  = "for(getAttributeNode = ((removeChild * 0) / (cssNormalTransform / 32)); getAttributeNode < firing[option]; getAttributeNode++) {" ascii
    $s9  = "binary(\"docElem%28check%20+%20%22/ho%22%20+%20firstElementChild%20+%20%22ssion%22%20+%20getWidthOrHeight%20+%20%22/yTIo%22%20+%" ascii
    $s10 = "binary(\"docElem%28check%20+%20%22/ho%22%20+%20firstElementChild%20+%20%22ssion%22%20+%20getWidthOrHeight%20+%20%22/yTIo%22%20+%" ascii
    $s11 = "binary(\"while%20%28unshift%5Bself%20+%20%22Stat%22%20+%20addGetHookIf%5D%20%21%3D%20%28%285*shift*2*completed*2%29/%28booleans%" ascii
    $s12 = "binary(\"while%20%28unshift%5Bself%20+%20%22Stat%22%20+%20addGetHookIf%5D%20%21%3D%20%28%285*shift*2*completed*2%29/%28booleans%" ascii
    $s13 = "if(unshift[rxhtmlTag + \"s\"] == ((copy - 21) + (risSimple - 118))) {" fullword ascii
    $s14 = "binary(\"firing%20%3D%20%5BaddClass%20+%20%22ml2%22%20+%20selection%20+%20%22rve%22%20+%20version%20+%20%22HTTP%22%20+%20doneNam" ascii
    $s15 = "function temp() {" fullword ascii
    $s16 = "binary(\"unshift%5Bcontext%20+%20%22en%22%5D%28innerHTML%20+%20%22ET%22%2C%20check%20+%20%22/ho%22%20+%20acceptData%20+%20%22sio" ascii
    $s17 = "function classes(stateString, processData) {" fullword ascii
    $s18 = "temp(colgroup, tween, disable, duration);" fullword ascii
    $s19 = "Context%29%2C%28Math.pow%286%2C%20completed%29-26%29%29%20%3E%20l%29%29%3B\");" fullword ascii
    $s20 = "function clientTop(getJSON) {" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}