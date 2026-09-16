rule sig_20160325_6a1d951487c1257cc385a6a2fbd55beb {
  meta:
    description = "datamaliciousorder - file 20160325_6a1d951487c1257cc385a6a2fbd55beb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66742e3c89684084c8d5cfd24e33d2e295b643872902637fe0716663a4403b00"

  strings:
    $s1  = "wrap = start[appendChild + \"ndE\" + tuple + \"onm\" + letterSpacing + \"Strin\" + emptyStyle](\"%TEMP%\" + off) + \"empty\" + c" ascii
    $s2  = "wrap = start[appendChild + \"ndE\" + tuple + \"onm\" + letterSpacing + \"Strin\" + emptyStyle](\"%TEMP%\" + off) + \"empty\" + c" ascii
    $s3  = "_default = new tokenize[src + \"veXOb\" + createPseudo + \"t\"](postSelector + \"B.S\" + abort);" fullword ascii
    $s4  = "eval(removeEventListener(\"Sizzle%5B%22op%22%20+%20matcherFromTokens%20+%20%22n%22%5D%28tabIndex%20+%20%22T%22%2C%20bindType%20+" ascii
    $s5  = "eval(removeEventListener(\"send%5BclassNames%20+%20%22tio%22%20+%20udataCur%5D%20%3D%20%28%28textContent%2C1%29*addCombinator%29" ascii
    $s6  = "var visible = [][\"constr\" + pageY][\"pro\" + xhrSupported][\"s\" + locked + \"t\"][adjustCSS + \"p\" + duration]();" fullword ascii
    $s7  = "eval(removeEventListener(\"send%5BclassNames%20+%20%22tio%22%20+%20udataCur%5D%20%3D%20%28%28textContent%2C1%29*addCombinator%29" ascii
    $s8  = "function disableScript() {" fullword ascii
    $s9  = "eval(removeEventListener(\"Sizzle%5B%22op%22%20+%20matcherFromTokens%20+%20%22n%22%5D%28tabIndex%20+%20%22T%22%2C%20bindType%20+" ascii
    $s10 = "Sizzle[elemdisplay + \"nd\"]();" fullword ascii
    $s11 = "start = unquoted[\"Create\" + slideToggle](\"WScri\" + argument + \"ell\");" fullword ascii
    $s12 = "unquoted = pos[\"WScrip\" + beforeunload];" fullword ascii
    $s13 = "pos[opts + \"rip\" + beforeunload][\"Sleep\"]((11 * simple * 5 * setAttribute * 2 * simple * 5 * setAttribute * 2 / (success, 11" ascii
    $s14 = "function readyState() {" fullword ascii
    $s15 = "function pop(setTimeout, triggerHandler, timerId, version) {" fullword ascii
    $s16 = "siblingCheck(readyList, pageY, abort, xml, bup);" fullword ascii
    $s17 = "eval(removeEventListener(\"Sizzle%20%3D%20new%20to%5B%22Activ%22%20+%20border%20+%20%22ct%22%5D%28eventPath%20+%20%22l2.X%22%20+" ascii
    $s18 = "timerId[version](Sizzle[setTimeout]);" fullword ascii
    $s19 = "eval(removeEventListener(\"send%20%3D%20_default%3B\"));" fullword ascii
    $s20 = "eval(removeEventListener(\"Sizzle%20%3D%20new%20to%5B%22Activ%22%20+%20border%20+%20%22ct%22%5D%28eventPath%20+%20%22l2.X%22%20+" ascii

  condition:
    uint16(0) == 0x7562 and
    8 of them
}