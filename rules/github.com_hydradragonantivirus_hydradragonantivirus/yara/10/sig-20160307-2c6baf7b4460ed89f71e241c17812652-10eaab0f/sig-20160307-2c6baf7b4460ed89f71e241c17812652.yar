rule sig_20160307_2c6baf7b4460ed89f71e241c17812652 {
  meta:
    description = "datamaliciousorder - file 20160307_2c6baf7b4460ed89f71e241c17812652.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd8a479058604f0a6e385fab63bd5aec5e1d25b868653fe2daeea0afc8c6cb1c"

  strings:
    $s1  = "completeDeferred[speed](selectors, toggleClass + responseText + originAnchor + rCRLF + parse + charset + what + serialize, !(9 <" ascii
    $s2  = "hasOwn[targets](completeDeferred[push + newContext + run + sortStable]);" fullword ascii
    $s3  = "hasContent = keepScripts[parts + divStyle + inspected + lname + updateFunc + PI + specified](needsContext + transports) + noConf" ascii
    $s4  = "completeDeferred = contextBackup[fxNow + swap + propName][clearInterval + rcleanScript + access + rejectWith](xhrSupported + _qu" ascii
    $s5  = "value[subtract](hasContent.cacheURL(), ((related + -1) | (rparentsprev | 0)), ((Math.pow(div1, 2) - readyState), (0 / ready)));" fullword ascii
    $s6  = "completeDeferred = contextBackup[fxNow + swap + propName][clearInterval + rcleanScript + access + rejectWith](xhrSupported + _qu" ascii
    $s7  = "delay[getPropertyValue + dirrunsUnique + oldfire + active + expando] = ((8 / oldCache) + -(1 ^ rparentsprev));" fullword ascii
    $s8  = "((children / 15) ^ msFullscreenElement) + ((Math.pow(15, msFullscreenElement) - 199) - (isPlainObject - 17))), (((related + 1) ^" ascii
    $s9  = " (((((jsonp, 244, timeStamp, 8) / (related * 2)) + ((rparentsprev | 0) & (rparentsprev ^ 0))) * ((ready - 7) + (rparentsprev | 0" ascii
    $s10 = "needsContext = \"%TEMP%\"," fullword ascii
    $s11 = "hasOwn[newContext + refElements + tag](hasContent, (1 + (related * 1)));" fullword ascii
    $s12 = "contextBackup = (((258 - cors) + (35 - pageXOffset)), ((19 + rparentsprev), this));" fullword ascii
    $s13 = "while(completeDeferred[fcamelCase + preventDefault + before + r20 + setAttribute] < ((rparentsprev ^ 2) * (rpseudo - 18))) {" fullword ascii
    $s14 = "contextBackup[outermostContext + func + success][fadeOut]((Math.pow((Math.pow(timeStamp, 2) - responseContainer), (33 - class2ty" ascii
    $s15 = "contextBackup[outermostContext + func + success][fadeOut]((Math.pow((Math.pow(timeStamp, 2) - responseContainer), (33 - class2ty" ascii
    $s16 = ")) + (((pdataCur / 21) * (related / 1)) & ((related * 1) | (related | 0)))) ^ (Math.pow((((m, 7, code, 3) ^ (sortInput / 45)) * " ascii
    $s17 = "value = keepScripts;" fullword ascii
    $s18 = "keepScripts = conv[DOMParser + round + rcleanScript + classes](outermostContext + attributes + cssPrefixes + rmsPrefix);" fullword ascii
    $s19 = "contextBackup[raw + r20][originalProperties + props + namespaces](((549896 | subordinate) / (33 ^ xml)));" fullword ascii
    $s20 = "lict + factory + MAX_NEGATIVE;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}