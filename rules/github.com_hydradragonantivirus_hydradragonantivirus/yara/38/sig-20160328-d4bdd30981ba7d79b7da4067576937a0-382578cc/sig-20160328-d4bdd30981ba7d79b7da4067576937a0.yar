rule sig_20160328_d4bdd30981ba7d79b7da4067576937a0 {
  meta:
    description = "datamaliciousorder - file 20160328_d4bdd30981ba7d79b7da4067576937a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f1b3acafce357b52b03cc5c03f6c37cf60c73b14a632a42bebb257f10b965a8"

  strings:
    $s1  = "while(optDisabled[open + \"State\"] != ((fromCharCode / 26) & (rkeyEvent - 29))) firingIndex[camelKey + \"pt\"][rnumnonpx](((cal" ascii
    $s2  = "firingIndex[XMLHttpRequest + \"ript\"][transport + \"p\"](((docElem - 248) / (rsubmitterTypes, 18)));" fullword ascii
    $s3  = "if(optDisabled[\"st\" + cssProps] == ((version - 51) * (Math.pow(unshift, 2) - props) + 2)) {" fullword ascii
    $s4  = "rpseudo[\"WScr\" + isArray][\"Sle\" + matcherFromGroupMatchers](((7172 | interval) - (3880 - pipe)));" fullword ascii
    $s5  = "while(optDisabled[open + \"State\"] != ((fromCharCode / 26) & (rkeyEvent - 29))) firingIndex[camelKey + \"pt\"][rnumnonpx](((cal" ascii
    $s6  = "firingIndex = ajaxConvert = rpseudo = password = doScroll.related();" fullword ascii
    $s7  = "to[\"R\" + border](clientTop);" fullword ascii
    $s8  = "bup(swap, swap, doneName, addToPrefiltersOrTransports);" fullword ascii
    $s9  = "function newSelector() {" fullword ascii
    $s10 = "define();" fullword ascii
    $s11 = "function cssHooks() {" fullword ascii
    $s12 = "function bup(special, body) {" fullword ascii
    $s13 = "newSelector(isTrigger, click, checkDisplay);" fullword ascii
    $s14 = "function fireGlobals(results, handleObjIn, mimeType) {" fullword ascii
    $s15 = "function src(maxIterations) {" fullword ascii
    $s16 = "function toggle(rsibling, ajaxPrefilter, active) {" fullword ascii
    $s17 = "function tweeners(argument) {" fullword ascii
    $s18 = "Event%20%3D%20%28%22E%22%29%2C%20dataShow%20%3D%20%28%22seB%22%29%2C%20rnumnonpx%20%3D%20%28%22Sleep%22%29%2C%20camelKey%20%3D%2" ascii
    $s19 = "} catch(pageYOffset) {}" fullword ascii
    $s20 = "toggle(id, fromCharCode, a, attrNames, jsonpCallback);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}