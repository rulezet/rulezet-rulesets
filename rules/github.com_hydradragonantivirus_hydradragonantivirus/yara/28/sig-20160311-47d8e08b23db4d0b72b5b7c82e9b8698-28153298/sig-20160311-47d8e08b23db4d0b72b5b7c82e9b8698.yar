rule sig_20160311_47d8e08b23db4d0b72b5b7c82e9b8698 {
  meta:
    description = "datamaliciousorder - file 20160311_47d8e08b23db4d0b72b5b7c82e9b8698.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81294fee5285e63a7f5711bdbf6fccfa94f3759dcedb2b6ab9c10026729f6ef8"

  strings:
    $x1  = "overflowX[\"op\" + raw](\"GE\" + nextSibling, \"http:\"._evalUrl() + focusin + \".moms\" + Symbol + \"om/08\" + splice, !(7 == (" ascii
    $s2  = "e - 44)) - (getScript | 209)) - ((id & 4) * (headers & 13) + (transports / 1))) * (((outerCache | 69) / (id * 3 + letter))), (((" ascii
    $s3  = "attrHandle = parse[overflowY + \"andEn\" + originalEvent + \"mentS\"._evalUrl() + input](\"%TEMP%\" + method) + \"fir\" + define" ascii
    $s4  = "attrHandle = parse[overflowY + \"andEn\" + originalEvent + \"mentS\"._evalUrl() + input](\"%TEMP%\" + method) + \"fir\" + define" ascii
    $s5  = "sibling = ((Math.pow(48, transports) - (322 * id + 318)), (andSelf + (1 + selection)), eval(\"th\" + showHide));" fullword ascii
    $s6  = "overflowX[\"op\" + raw](\"GE\" + nextSibling, \"http:\"._evalUrl() + focusin + \".moms\" + Symbol + \"om/08\" + splice, !(7 == (" ascii
    $s7  = "1 + slideToggle) * 3 * (file - 26) * (compile - 51) - ((createInputPseudo, 239, click) - (1122 / unbind))) + (((1530 & setFilter" ascii
    $s8  = "_default[removeEvent + \"un\"](attrHandle._evalUrl(((selection | 37) + (Math.pow(file, 2) - fixInput))), ((1 * selection) & (30 " ascii
    $s9  = "_default[removeEvent + \"un\"](attrHandle._evalUrl(((selection | 37) + (Math.pow(file, 2) - fixInput))), ((1 * selection) & (30 " ascii
    $s10 = "gle + 1) + ((write & 61) - (originalSettings + 35))) * (((Math.pow(jsonProp, 2) - bubbleType) - (1 * id)) - ((8 | slideToggle) |" ascii
    $s11 = "function manipulationTarget() {" fullword ascii
    $s12 = "defaultPrevented = \"ct\", radio = \"WScrip\", compare = \"ript\", transports = 2, locked = \"t\";" fullword ascii
    $s13 = "list = 45, setFilters = 2047, rxhtmlTag = \"rit\", headers = 12, createInputPseudo = 15;" fullword ascii
    $s14 = "hidden[\"saveTo\" + jsonp](attrHandle, (selection | 2));" fullword ascii
    $s15 = "hidden = sibling[radio + \"t\"][body + \"Obje\"._evalUrl() + defaultPrevented](\"ADO\" + cssProps + \"ream\");" fullword ascii
    $s16 = "overflowX = sibling[max + \"pt\"._evalUrl()][body + \"Objec\" + locked](\"MSXML\" + origType + \"LHTT\"._evalUrl() + definePrope" ascii
    $s17 = "_queueHooks[\"t\" + matchesSelector + \"p\" + hasDuplicate] = ((oMatchesSelector & 26) - letter * 5);" fullword ascii
    $s18 = "parse = off[\"Cre\" + rnoInnerhtml + \"ject\"](els + \"ript.\"._evalUrl() + genFx + \"l\");" fullword ascii
    $s19 = "evalUrl() + attrHooks + \"s\" + show + \"r\";" fullword ascii
    $s20 = "off = sibling[\"WScr\"._evalUrl() + origName];" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    1 of ($x*) and 4 of them
}