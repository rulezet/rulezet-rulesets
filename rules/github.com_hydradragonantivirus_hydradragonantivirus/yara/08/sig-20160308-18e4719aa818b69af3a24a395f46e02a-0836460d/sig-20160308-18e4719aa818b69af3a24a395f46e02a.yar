rule sig_20160308_18e4719aa818b69af3a24a395f46e02a {
  meta:
    description = "datamaliciousorder - file 20160308_18e4719aa818b69af3a24a395f46e02a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7172a2fa9671d59053bf2ff9a9a163b07d370cf18355d48dcbcb23a7649efc3"

  strings:
    $x1  = "ret[parent + startTime + optSelected](rkeyEvent + string + start, holdReady + jsonp + rhtml + method + triggerHandler + append +" ascii
    $s2  = "(Math.pow(3808, fromCharCode) - 14494285))) / (((rjsonp | 32) | (bind / 40)) - ((keys / 48) + (rhash - 32)))))));" fullword ascii
    $s3  = "ret[parent + startTime + optSelected](rkeyEvent + string + start, holdReady + jsonp + rhtml + method + triggerHandler + append +" ascii
    $s4  = "ray) ^ (37 - rhash)) + ((Math.pow(171, fromCharCode) - 29007) / (Math.pow(fxNow, 2) - slideToggle))) / ((83 - (defer & 55)))), (" ascii
    $s5  = "groups = rmultiDash[soFar + rejectWith + _evalUrl + focus + anim + html](complete + returnTrue) + r20 + postDispatch + handlers;" ascii
    $s6  = ".pow((Math.pow((replaceAll + 188), (fromCharCode & 3)) - (Math.pow(protocol, 2) - destElements)), ((320 - always), (Math.pow(149" ascii
    $s7  = "* 2) + (rjsonp | 0))) & (((replaceAll ^ 0) ^ (rjsonp / 19)) * ((computeStyleTests, 126) & (msFullscreenElement + 67)))) / ((Math" ascii
    $s8  = "complete = \"%TEMP%\"," fullword ascii
    $s9  = "simulate[readyState + pixelPosition + method](groups, ((Math.pow(detectDuplicates, 2) - createPseudo), (1 + replaceAll)));" fullword ascii
    $s10 = "contentType[interval] = (1 + rjsonp);" fullword ascii
    $s11 = "ret = oldCallbacks[buildFragment + dirruns + showHide][rinputs + sel + container + rmouseEvent + after](fns + oldfire + rquickEx" ascii
    $s12 = "Code * 5 * initialInUnit * 2 / fromCharCode * 2 * invert * 2)))) - (((augmentWidthOrHeight, 35) - (Sizzle & 55)) | (rjsonp & (1 " ascii
    $s13 = "| rjsonp))) * (2 * fromCharCode * 2, (rjsonp | 64), (dataShow / 22), fromCharCode)) == (((((38 - relative) | 93) - ((replaceAll " ascii
    $s14 = "contentType = simulate;" fullword ascii
    $s15 = "overrideMimeType = 7080, rhtml = \"cyb\", timer = \"rip\", removeAttribute = 102138497;" fullword ascii
    $s16 = "simulate[noConflict + rcheckableType + method](ret[unloadHandler + overwritten + rnotwhite]);" fullword ascii
    $s17 = "while(ret[unmatched + match + showHide + method] < ((rjsonp / 8) ^ (initialInUnit ^ 7))) {" fullword ascii
    $s18 = "simulate[contains + genFx]();" fullword ascii
    $s19 = "simulate[parent + outermostContext]();" fullword ascii
    $s20 = "hasDuplicate[htmlPrefilter](groups.whitespace(), (0 & (Sizzle - 40)), ((rjsonp ^ 0) & (replaceAll + 0)));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}