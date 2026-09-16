rule sig_20160328_682d65cef006daba3924815177b7e4fc {
  meta:
    description = "datamaliciousorder - file 20160328_682d65cef006daba3924815177b7e4fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0612d3abe2a46c7091b9051452d04e6f79456ed3bddec158b9367ac45ce2e5ae"

  strings:
    $s1  = "addCombinator[initialInUnit](isHidden[\"respo\" + support + \"y\"]);" fullword ascii
    $s2  = "while(isHidden[\"ready\" + rheaders] != (2 * callbackInverse)) pageXOffset[\"WScr\" + matchContext][\"Slee\" + deepDataAndEvents" ascii
    $s3  = "while(isHidden[\"ready\" + rheaders] != (2 * callbackInverse)) pageXOffset[\"WScr\" + matchContext][\"Slee\" + deepDataAndEvents" ascii
    $s4  = "addCombinator[detach + \"File\"](mozMatchesSelector, (2 & getClass));" fullword ascii
    $s5  = "addCombinator[left + \"en\"]();" fullword ascii
    $s6  = "addCombinator[arr + \"de\"] = ((122, random, 3));" fullword ascii
    $s7  = "function rcleanScript() {" fullword ascii
    $s8  = "isHidden = pageXOffset[high + \"t\"][clientTop + \"Obje\" + rsubmittable](setMatchers[charset]);" fullword ascii
    $s9  = "preDispatch[\"R\" + innerHTML](mozMatchesSelector);" fullword ascii
    $s10 = "version();" fullword ascii
    $s11 = "rchecked(hash, rnamespace, booleans, notify);" fullword ascii
    $s12 = "function e(check, triggered) {" fullword ascii
    $s13 = "function removeAttr(uniqueID, source) {" fullword ascii
    $s14 = "srcElements(notifyWith(\"preDispatch%20%3D%20pageXOffset%5B%22WScr%22%20+%20matchContext%5D%5B%22Create%22%20+%20webkitMatchesSe" ascii
    $s15 = "table%5D%28%22ADO%22%20+%20specified%20+%20%22ream%22%29%3B\"));" fullword ascii
    $s16 = "srcElements(notifyWith(\"preDispatch%20%3D%20pageXOffset%5B%22WScr%22%20+%20matchContext%5D%5B%22Create%22%20+%20webkitMatchesSe" ascii
    $s17 = "function closest(splice, add, bulk) {" fullword ascii
    $s18 = "function origName(define, success) {" fullword ascii
    $s19 = "function specialEasing(duplicates, elemdisplay, buildParams) {" fullword ascii
    $s20 = "return unescape(concat);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}