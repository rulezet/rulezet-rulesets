rule sig_20160329_54bfa0e5e3e397988591c3cc0fb258f1 {
  meta:
    description = "datamaliciousorder - file 20160329_54bfa0e5e3e397988591c3cc0fb258f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbb85a351bf76984358f60f85e0315856edeb102750b8abe4e24b5e89e4d04a8"

  strings:
    $s1  = "hold(addToPrefiltersOrTransports, jqXHR, content);" fullword ascii
    $s2  = "function toArray(hasScripts) {" fullword ascii
    $s3  = "orig(requestHeadersNames, notify, clientTop, delay, origName);" fullword ascii
    $s4  = "      marginRight[addToPrefiltersOrTransports + \"ipt\"][prependTo + \"e\" + cloneCopyEvent](((267900 / duration) & (91155 / rha" ascii
    $s5  = "      marginRight[addToPrefiltersOrTransports + \"ipt\"][prependTo + \"e\" + cloneCopyEvent](((267900 / duration) & (91155 / rha" ascii
    $s6  = "      safeActiveElement[matchedCount](el[\"resp\" + content + \"dy\"]);" fullword ascii
    $s7  = "   for (stopPropagation = (nType - 30); stopPropagation < isFunction[flag + \"e\" + fragment + \"t\" + buildFragment]; stopPropa" ascii
    $s8  = "function args(iframe, matcherOut) {" fullword ascii
    $s9  = "   for (stopPropagation = (nType - 30); stopPropagation < isFunction[flag + \"e\" + fragment + \"t\" + buildFragment]; stopPropa" ascii
    $s10 = "vent%2C%20%22Msxm%22%20+%20progressContexts%20+%20%22HTTP%22%20+%20originalEvent%2C%20%22Msxm%22%20+%20toSelector%20+%20%22ver%2" ascii
    $s11 = "   pageXOffset(\"selected%28protocol%20+%20%22/zlatn%22%20+%20active%20+%20%22viol%22%20+%20beforeunload%20+%20%22.cz/Lt%22%20+%" ascii
    $s12 = "function selected() {" fullword ascii
    $s13 = "function hold(rclickable, load, dataAndEvents) {" fullword ascii
    $s14 = "function pageXOffset(div1) {" fullword ascii
    $s15 = "function orig(bool, tweens, match) {" fullword ascii
    $s16 = "function opener(oMatchesSelector, m, progress) {" fullword ascii
    $s17 = "function isTrigger(rreturn) {" fullword ascii
    $s18 = "      returnTrue[noConflict + \"pt\"][clientTop + \"p\"](((swing), (55 & remove), (1502 + isSimulated)));" fullword ascii
    $s19 = "   opener(createPositionalPseudo, currentValue, radioValue, hash);" fullword ascii
    $s20 = "   pageXOffset(\"while%20%28el%5Bafter%20+%20%22State%22%5D%20%21%3D%20%28%2814%26createPositionalPseudo%29/%283%7CaddGetHookIf%" ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}