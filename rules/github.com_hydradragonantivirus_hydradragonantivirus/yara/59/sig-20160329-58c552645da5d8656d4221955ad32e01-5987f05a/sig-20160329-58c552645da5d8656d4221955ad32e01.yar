rule sig_20160329_58c552645da5d8656d4221955ad32e01 {
  meta:
    description = "datamaliciousorder - file 20160329_58c552645da5d8656d4221955ad32e01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02e86e0dabd5fce9d5b9943d610c30d2a484663f6118ef4db9de1cb527ad203c"

  strings:
    $s1  = "      Expr[\"WScrip\" + rkeyEvent][\"Sleep\"](((msg - 123521) / (timer / 50)));" fullword ascii
    $s2  = "      offset[addGetHookIf + \"u\" + temp](pdataCur);" fullword ascii
    $s3  = "   curElem(\"traditional%5B%22o%22%20+%20extra%20+%20%22n%22%5D%28num%20+%20%22E%22%20+%20keyHooks%2C%20%22htt%22%20+%20classNam" ascii
    $s4  = "Expr = err = keepScripts = soFar = compareDocumentPosition.wrapInner();" fullword ascii
    $s5  = "   if(traditional[restoreScript + \"tatus\"] == ((768 | matchAnyContext) / (57 - actualDisplay))) {" fullword ascii
    $s6  = "function curElem(password) {" fullword ascii
    $s7  = "         traditional = soFar[param + \"pt\"][_ + \"Objec\" + rkeyEvent](has[rparentsprev]);" fullword ascii
    $s8  = "   for(rparentsprev = (0 / (Math.pow(div1, 2) - document)); rparentsprev < has[set + \"h\"]; rparentsprev++) {" fullword ascii
    $s9  = "      one[newUnmatched + \"pe\" + temp]();" fullword ascii
    $s10 = "newCache(dirrunsUnique, temp);" fullword ascii
    $s11 = "function postFinder(node, udataOld) {" fullword ascii
    $s12 = "function overflowY(forward) {" fullword ascii
    $s13 = "         traditional[restoreScript + \"en\" + implementation]();" fullword ascii
    $s14 = "overflowX(origCount, when, addGetHookIf);" fullword ascii
    $s15 = "postFinder(splice, margin, splice, _);" fullword ascii
    $s16 = "function get(root, rescape, teardown) {" fullword ascii
    $s17 = "   curElem(\"while%20%28traditional%5B%22read%22%20+%20hasScripts%20+%20%22te%22%5D%20%21%3D%20%28%28tuple*9+fadeOut%29/%2822+wh" ascii
    $s18 = "function matcherFromTokens() {" fullword ascii
    $s19 = "   curElem(\"offset%20%3D%20err%5B%22WScr%22%20+%20cssHooks%5D%5B%22Cre%22%20+%20rcssNum%20+%20%22bjec%22%20+%20rkeyEvent%5D%28%" ascii
    $s20 = "function valHooks(rtrim, addEventListener, rnotwhite) {" fullword ascii

  condition:
    uint16(0) == 0x6c65 and
    8 of them
}