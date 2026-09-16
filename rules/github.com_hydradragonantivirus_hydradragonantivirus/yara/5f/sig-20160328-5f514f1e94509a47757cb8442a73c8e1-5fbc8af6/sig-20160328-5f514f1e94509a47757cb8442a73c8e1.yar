rule sig_20160328_5f514f1e94509a47757cb8442a73c8e1 {
  meta:
    description = "datamaliciousorder - file 20160328_5f514f1e94509a47757cb8442a73c8e1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbea2e0f2c8f23a7534fa27dfa77c805f0e770d42de4a671a368d2a59d0df282"

  strings:
    $x1  = "eval(pageXOffset(\"Sizzle%20%3D%20%28%22oft.%22%29%2C%20specialEasing%20%3D%20%28%222.X%22%29%2C%20swap%20%3D%20%28%22d.exe%22%2" ascii
    $s2  = "getElementsByName[\"WSc\" + dataType][\"Sleep\"](((Math.pow(215, matcherFromTokens) - 45992), (requestHeaders - 65), (tweeners +" ascii
    $s3  = "while (indirect[arg + \"tat\" + win] != (2 * (Deferred - 46))) getElementsByName[\"WScr\" + rcomma][\"Sl\" + win + \"e\" + cross" ascii
    $s4  = "while (indirect[arg + \"tat\" + win] != (2 * (Deferred - 46))) getElementsByName[\"WScr\" + rcomma][\"Sl\" + win + \"e\" + cross" ascii
    $s5  = "if (indirect[\"st\" + tuple] == ((Math.pow(split, 2) - appendTo) | (226, rmsPrefix, 113, fns))) {" fullword ascii
    $s6  = "matchedCount[seed + \"ToFil\" + win](setOffset, ((33 - delegate) & (38 / hover)));" fullword ascii
    $s7  = "eval(pageXOffset(\"Sizzle%20%3D%20%28%22oft.%22%29%2C%20specialEasing%20%3D%20%28%222.X%22%29%2C%20swap%20%3D%20%28%22d.exe%22%2" ascii
    $s8  = "rsubmittable(pageXOffset(\"preDispatch%20%3D%20%5B%22Msx%22%20+%20duration%20+%20%22.Se%22%20+%20pseudos%20+%20%22XML%22%20+%20i" ascii
    $s9  = "function conditionFn(a, head) {" fullword ascii
    $s10 = "function overrideMimeType() {" fullword ascii
    $s11 = "indirect = closest[cloneCopyEvent + \"ipt\"][get + \"ateOb\" + until](preDispatch[duplicates]);" fullword ascii
    $s12 = "indirect[\"se\" + boxSizingReliableVal + \"d\"]();" fullword ascii
    $s13 = "for (duplicates = ((initialInUnit + -1) / (attaches & 15)); duplicates < preDispatch[adown + \"h\"]; duplicates++) {" fullword ascii
    $s14 = "function addCombinator(reliableMarginRight, clientLeft) {" fullword ascii
    $s15 = "root(rbuggyQSA);" fullword ascii
    $s16 = "andSelf(checked, configurable, sortOrder, preventDefault);" fullword ascii
    $s17 = "addCombinator(backgroundClip, until);" fullword ascii
    $s18 = "Local%20+%20%22.0%22%2C%20stopImmediatePropagation%20+%20%22l2.%22%20+%20firstDataType%20+%20%22HTT%22%20+%20binary%20+%20%22.0%" ascii
    $s19 = "rsubmittable(pageXOffset(\"indirect%5B%22op%22%20+%20win%20+%20%22n%22%5D%28tuples%20+%20%22ET%22%2C%20checked%20+%20%22/z-14%22" ascii
    $s20 = "function optall() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}