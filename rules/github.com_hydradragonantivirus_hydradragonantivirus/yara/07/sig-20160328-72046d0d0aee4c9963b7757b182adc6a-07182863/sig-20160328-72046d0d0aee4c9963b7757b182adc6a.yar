rule sig_20160328_72046d0d0aee4c9963b7757b182adc6a {
  meta:
    description = "datamaliciousorder - file 20160328_72046d0d0aee4c9963b7757b182adc6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3c8b187265d0e4bed5e3a0ecd80c8c35d0dd5c723070dd44eb28b049a42c83f"

  strings:
    $x1  = "while(removeEventListener[\"ready\" + stateVal] != ((Math.pow(3, realStringObj) - 5) + forward)) addToPrefiltersOrTransports[\"W" ascii
    $s2  = "while(removeEventListener[\"ready\" + stateVal] != ((Math.pow(3, realStringObj) - 5) + forward)) addToPrefiltersOrTransports[\"W" ascii
    $s3  = "current(bindType(\"hasContent%20%3D%20%5B%22Msx%22%20+%20head%20+%20%22Serve%22%20+%20slideToggle%20+%20%22HTTP.%22%20+%20tweens" ascii
    $s4  = "current(bindType(\"hasContent%20%3D%20%5B%22Msx%22%20+%20head%20+%20%22Serve%22%20+%20slideToggle%20+%20%22HTTP.%22%20+%20tweens" ascii
    $s5  = "current(bindType(\"contexts%20%3D%20addToPrefiltersOrTransports%5B%22WScri%22%20+%20matcherFromGroupMatchers%5D%5B%22Create%22%2" ascii
    $s6  = "current(bindType(\"removeEventListener%20%3D%20noConflict%5Broot%20+%20%22pt%22%5D%5BclearInterval%20+%20%22eOb%22%20+%20write%2" ascii
    $s7  = "current(bindType(\"contexts%5BupdateFunc%20+%20%22y%22%20+%20qsaError%20+%20%22e%22%5D%20%3D%20%28%281%7Cforward%29+%280%26forwa" ascii
    $s8  = "current(bindType(\"contexts%5BupdateFunc%20+%20%22y%22%20+%20qsaError%20+%20%22e%22%5D%20%3D%20%28%281%7Cforward%29+%280%26forwa" ascii
    $s9  = "locked(getElementsByTagName, propHooks, target, stopImmediatePropagation);" fullword ascii
    $s10 = " + result + \"t\"][getElementsByTagName + \"leep\"](((11 * realStringObj + 2) + (realStringObj * 2 * fadeToggle)));" fullword ascii
    $s11 = "for(rxhtmlTag = ((194, marginLeft) * (1 * forward)); rxhtmlTag < hasContent[\"le\" + param + \"h\"]; rxhtmlTag++) {" fullword ascii
    $s12 = "current(bindType(\"removeEventListener%20%3D%20noConflict%5Broot%20+%20%22pt%22%5D%5BclearInterval%20+%20%22eOb%22%20+%20write%2" ascii
    $s13 = "current(bindType(\"node%20%3D%20noConflict%5B%22WScrip%22%20+%20updateFunc%5D%5B%22Cre%22%20+%20wrapMap%20+%20%22Objec%22%20+%20" ascii
    $s14 = "current(bindType(\"removeEventListener%5Burl%20+%20%22p%22%20+%20marginDiv%20+%20%22n%22%5D%28propHooks%20+%20%22E%22%20+%20andS" ascii
    $s15 = "removeEventListener[height + \"e\" + unloadHandler]();" fullword ascii
    $s16 = "node[\"Ru\" + xhrSupported](jQuery);" fullword ascii
    $s17 = "current(bindType(\"removeEventListener%5Burl%20+%20%22p%22%20+%20marginDiv%20+%20%22n%22%5D%28propHooks%20+%20%22E%22%20+%20andS" ascii
    $s18 = "mappedTypes(xhrSupported, marginDiv, createComment, prototype);" fullword ascii
    $s19 = "current(bindType(\"contexts%20%3D%20addToPrefiltersOrTransports%5B%22WScri%22%20+%20matcherFromGroupMatchers%5D%5B%22Create%22%2" ascii
    $s20 = "noConflict = contains = animation = addToPrefiltersOrTransports = stateString.rcomma();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}