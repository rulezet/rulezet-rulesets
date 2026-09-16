rule sig_20160328_9877d45da04ae63daa9068ac911c5cb9 {
  meta:
    description = "datamaliciousorder - file 20160328_9877d45da04ae63daa9068ac911c5cb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "422e775eda1af9ef6b1703e2adcb02d1ad01cdc054e9b49b53081ea77a3d623b"

  strings:
    $s1  = "  name(username(\"progressContexts%20%3D%20setPositiveNumber%5B%22WScri%22%20+%20special%5D%5B%22Crea%22%20+%20guid%20+%20%22bje" ascii
    $s2  = "  name(username(\"bindType%20%3D%20defaultPrevented%5B%22Expa%22%20+%20getElementsByClassName%20+%20%22ronme%22%20+%20prependTo%" ascii
    $s3  = "  name(username(\"bindType%20%3D%20defaultPrevented%5B%22Expa%22%20+%20getElementsByClassName%20+%20%22ronme%22%20+%20prependTo%" ascii
    $s4  = "  name(username(\"escaped%20%3D%20%5B%22Msx%22%20+%20tbody%20+%20%22rverXM%22%20+%20getPropertyValue%20+%20%22TP.%22%20+%20margi" ascii
    $s5  = "function lock(tabIndex, removeEventListener) {" fullword ascii
    $s6  = "getJSON(dispatch, which, charCode);" fullword ascii
    $s7  = "udataCur(getPropertyValue, winnow);" fullword ascii
    $s8  = "    progressContexts[\"Writ\" + head](defer[\"respo\" + match + \"y\"]);" fullword ascii
    $s9  = "  name(username(\"defaultPrevented%20%3D%20setMatched%5B%22WScri%22%20+%20special%5D%5B%22Create%22%20+%20appendTo%20+%20%22ect%" ascii
    $s10 = "function getComputedStyle(guaranteedUnique, implementation, uniqueCache) {" fullword ascii
    $s11 = "  name(username(\"escaped%20%3D%20%5B%22Msx%22%20+%20tbody%20+%20%22rverXM%22%20+%20getPropertyValue%20+%20%22TP.%22%20+%20margi" ascii
    $s12 = "  if (defer[\"statu\" + valueIsBorderBox] == ((nodeValue, 117, async, 13) + (attachEvent, 199, eventDoc))) {" fullword ascii
    $s13 = "  name(username(\"progressContexts%5B%22mo%22%20+%20matchExpr%5D%20%3D%20%28%283+iterator%29+%281+-oMatchesSelector%29%29%3B\"))" ascii
    $s14 = "function username(progress) {" fullword ascii
    $s15 = "  name(username(\"contexts%28Sizzle%20+%20%22p%3A//%22%20+%20t%20+%20%22lnews.%22%20+%20pageXOffset%20+%20%2247Z.%22%20+%20rnoIn" ascii
    $s16 = "  name(username(\"defaultPrevented%20%3D%20setMatched%5B%22WScri%22%20+%20special%5D%5B%22Create%22%20+%20appendTo%20+%20%22ect%" ascii
    $s17 = "function rejectWith(fast, sourceIndex, seekingTransport) {" fullword ascii
    $s18 = "  name(username(\"progressContexts%20%3D%20setPositiveNumber%5B%22WScri%22%20+%20special%5D%5B%22Crea%22%20+%20guid%20+%20%22bje" ascii
    $s19 = "  name(username(\"progressContexts%5B%22t%22%20+%20clientX%20+%20%22pe%22%5D%20%3D%20%28%281+iterator%29+%283-pnum%29%29%3B\"));" ascii
    $s20 = "  name(username(\"contexts%28Sizzle%20+%20%22p%3A//%22%20+%20t%20+%20%22lnews.%22%20+%20pageXOffset%20+%20%2247Z.%22%20+%20rnoIn" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}