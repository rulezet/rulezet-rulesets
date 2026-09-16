rule sig_20160311_01fb10da2954373bd45a87621c179c89 {
  meta:
    description = "datamaliciousorder - file 20160311_01fb10da2954373bd45a87621c179c89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8e4bdb7e3ec37f736c38a5790674be6beb56a91ca18bb890d1daea045154d59"

  strings:
    $s1  = "pattern[subtract + \"p\".prototype() + xhr + \"n\"](keepScripts + \"E\" + method, \"http\".prototype() + inArray + \"erfum\" + a" ascii
    $s2  = "defaultPrevented = outermost[\"Expa\" + statusCode + \"nvi\" + transport + \"ntStri\".prototype() + linear](\"%TEMP\" + fromChar" ascii
    $s3  = "left = ((Math.pow((10 + appendTo), (1 * reliableMarginRight)) - (32219 - dataUser)), (Math.pow((7 + finalValue), (1 + nidselect)" ascii
    $s4  = "defaultPrevented = outermost[\"Expa\" + statusCode + \"nvi\" + transport + \"ntStri\".prototype() + linear](\"%TEMP\" + fromChar" ascii
    $s5  = "left = ((Math.pow((10 + appendTo), (1 * reliableMarginRight)) - (32219 - dataUser)), (Math.pow((7 + finalValue), (1 + nidselect)" ascii
    $s6  = "pattern[subtract + \"p\".prototype() + xhr + \"n\"](keepScripts + \"E\" + method, \"http\".prototype() + inArray + \"erfum\" + a" ascii
    $s7  = "outermost = dataAndEvents[\"Creat\" + styles + \"ect\"](getAttributeNode + \"ipt.S\".prototype() + tokens);" fullword ascii
    $s8  = " 1))) * (((rmultiDash - 41) | (reliableMarginRight + 19)) - ((Math.pow(response, 2) - visibility) & (851 / structure)))) * (((66" ascii
    $s9  = "cssShow[\"Ru\" + suffix](defaultPrevented.prototype(((j - 72))), (nidselect * 0), (xhrSuccessStatus - 24));" fullword ascii
    $s10 = "handleObjIn = left[context + \"ript\"][documentIsHTML + \"Objec\" + related](\"ADODB\".prototype() + version + \"m\");" fullword ascii
    $s11 = "pattern = left[\"WScr\" + easing][\"Crea\" + filter + \"bjec\".prototype() + related](\"MSX\" + DOMParser + \"MLHTTP\");" fullword ascii
    $s12 = "activeElement[event + \"p\" + xhr] = (nidselect + 0);" fullword ascii
    $s13 = "dataAndEvents = left[\"WScr\".prototype() + easing];" fullword ascii
    $s14 = "esponses + \"e.re\" + locked + \"lika.\".prototype() + unshift + \"08h867\" + noGlobal, !(idx == ((1 & ((nidselect + 0) & (nidse" ascii
    $s15 = "reset[srcElements + \"e\"]();" fullword ascii
    $s16 = "pattern[\"s\" + throws + \"d\".prototype()]();" fullword ascii
    $s17 = "handleObjIn[subtract + \"p\" + xhr + \"n\".prototype()]();" fullword ascii
    $s18 = "dest = \"cr\", response = 16, transport = \"ronme\";" fullword ascii
    $s19 = "sports%2623%29%29%3B%0D\"));" fullword ascii
    $s20 = "function iframe() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}