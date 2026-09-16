rule sig_20160328_6959a3bac50d5d23e2d86260a238c2b1 {
  meta:
    description = "datamaliciousorder - file 20160328_6959a3bac50d5d23e2d86260a238c2b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0088dedbe1fa92eb22448923651b3a2afd3aee812cb44088828a1ebc595730d"

  strings:
    $x1  = "eval(name(\"var%20cacheURL%20%3D%20%28%22WScri%22%29%2C%20optgroup%20%3D%20%2817%29%2C%20err%20%3D%20%28%22LHTTP%22%29%2C%20tr%2" ascii
    $s2  = "ts, 2) - errorCallback) - (Math.pow(36, token) - 1236)));" fullword ascii
    $s3  = "    while (groups[\"readyS\" + pos] != ((1 * tr) & (123, r20, 6))) matchesSelector[\"WScr\" + preFilters][\"Sleep\"](((Math.pow(" ascii
    $s4  = "tabIndex[readyList + \"od\" + push] = ((52, protocol, 185), (matched & 239), (lastChild & 195), (timeStamp));" fullword ascii
    $s5  = "unction%20acceptData.dataUser%28%29%7Bvar%20els%3D%20%5B%5D%5B%22const%22%20+%20compiled%20+%20%22r%22%5D%5BhasOwn%20+%20%22tot%" ascii
    $s6  = "    rnumnonpx(name(\"tweeners%20%3D%20nodeIndex%5Bkeys%20+%20%22Envir%22%20+%20src%20+%20%22tStri%22%20+%20select%5D%28%22%25TEM" ascii
    $s7  = "scriptCharset(token, err, pos, currentTime);" fullword ascii
    $s8  = "function transports(addBack, matchExpr, addGetHookIf) {" fullword ascii
    $s9  = "reject = high = origName = matchesSelector = acceptData.dataUser();" fullword ascii
    $s10 = "    rnumnonpx(name(\"hasClass%20%3D%20%5B%22Msxml2%22%20+%20each%20+%20%22ver%22%20+%20values%20+%20%22TP.6.%22%20+%20camel%2C%2" ascii
    $s11 = "    rnumnonpx(name(\"groups%5B%22op%22%20+%20traditional%5D%28%22G%22%20+%20strAbort%20+%20%22T%22%2C%20sortStable%20+%20%22p%3A" ascii
    $s12 = "        tabIndex[timer + \"oFile\"](tweeners, ((attr - 68) - (owner & 47)));" fullword ascii
    $s13 = "282%20%3D%3D%20%28%28token*59*token%29%2C%2842/compareDocumentPosition%29%29%29%29%3B\"));" fullword ascii
    $s14 = "    rnumnonpx(name(\"tabIndex%20%3D%20matchesSelector%5B%22WSc%22%20+%20rkeyEvent%5D%5B%22Crea%22%20+%20multipleContexts%20+%20%" ascii
    $s15 = "function scriptCharset(which) {" fullword ascii
    $s16 = "    rnumnonpx(name(\"tabIndex%20%3D%20matchesSelector%5B%22WSc%22%20+%20rkeyEvent%5D%5B%22Crea%22%20+%20multipleContexts%20+%20%" ascii
    $s17 = "function rnoContent() {" fullword ascii
    $s18 = "    rnumnonpx(name(\"tweeners%20%3D%20nodeIndex%5Bkeys%20+%20%22Envir%22%20+%20src%20+%20%22tStri%22%20+%20select%5D%28%22%25TEM" ascii
    $s19 = "    while (groups[\"readyS\" + pos] != ((1 * tr) & (123, r20, 6))) matchesSelector[\"WScr\" + preFilters][\"Sleep\"](((Math.pow(" ascii
    $s20 = "function visible(bubbleType, rquickExpr, combinator) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}