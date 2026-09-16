rule sig_20160311_0397d1adadd51d58b8df43f76175b8e9 {
  meta:
    description = "datamaliciousorder - file 20160311_0397d1adadd51d58b8df43f76175b8e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c9297e08b8c81d6d45e43b086f14ee459b5a7e941eef6ff0686eb0c51bf3072"

  strings:
    $s1  = "prop[\"o\".hookFn() + mimeType + \"n\"](slideDown + \"T\", noConflict + \"/50.\".hookFn() + uid + \"11.\" + unit + \"d0/89o\" + " ascii
    $s2  = "), (toggle, 250, matchedCount, 33)) | (Math.pow((origType & 14), (getResponseHeader / 47)) - (rwhitespace - 171)))))));" fullword ascii
    $s3  = "rwhitespace = 297, isXML = \"%TEMP%\";" fullword ascii
    $s4  = ", isLocal, 72), (proxy & 127), (removeProp - 41)) + ((firstElementChild + 0) * firstElementChild)) * ((210, inArray, 167, fireWi" ascii
    $s5  = "prop = amd[\"WScr\" + rscriptTypeMasked][\"Crea\".hookFn() + groups + \"bject\"](ret + \".XMLH\" + handle);" fullword ascii
    $s6  = "input[\"Ru\" + status](toSelector.hookFn(((64 | ofType) - (2 * trim + 1))), (writable | (1 * writable)), ((90, write), (3, writa" ascii
    $s7  = "input[\"Ru\" + status](toSelector.hookFn(((64 | ofType) - (2 * trim + 1))), (writable | (1 * writable)), ((90, write), (3, writa" ascii
    $s8  = "prop[disconnectedMatch + \"e\" + dataUser]();" fullword ascii
    $s9  = "pointerenter = amd[\"WScrip\" + setOffset][\"Cre\".hookFn() + ridentifier + \"Obje\" + find](\"ADOD\" + t + \"tre\".hookFn() + t" ascii
    $s10 = "th) * (28 - callbackExpect) * (3 & createTextNode) * (251, trim) * (31 - completed) / ((484 / detach) + (18 | onlyHandlers))), (" ascii
    $s11 = "pipe = 10;" fullword ascii
    $s12 = "inLeft + \"y4\".hookFn(), !(pipe < ((((1 | writable)) * (1 + firstElementChild)) * (((26 / callbackExpect) * 5) * ((cleanData, 1" ascii
    $s13 = "toSelector = defaultDisplay[currentTime + \"andEnv\" + markFunction + \"nme\".hookFn() + unshift + \"ings\"](isXML + \"/\") + fu" ascii
    $s14 = "prop[\"o\".hookFn() + mimeType + \"n\"](slideDown + \"T\", noConflict + \"/50.\".hookFn() + uid + \"11.\" + unit + \"d0/89o\" + " ascii
    $s15 = "htmlPrefilter)) / ((212 + curCSSLeft), (88 - before), (252 / callbackInverse)))) - (((113 * createTextNode + 19), (timeout - 109" ascii
    $s16 = "stop = amd[createFxNow + \"t\"];" fullword ascii
    $s17 = " \"c\".hookFn() + original + \"c\" + not;" fullword ascii
    $s18 = "proxy = 107;" fullword ascii
    $s19 = "before = 19;" fullword ascii
    $s20 = "function eventPath() {" fullword ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}