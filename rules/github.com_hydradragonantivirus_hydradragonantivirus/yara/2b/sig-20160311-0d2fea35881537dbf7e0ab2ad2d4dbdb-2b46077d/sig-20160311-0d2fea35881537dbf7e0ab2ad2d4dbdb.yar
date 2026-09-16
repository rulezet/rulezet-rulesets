rule sig_20160311_0d2fea35881537dbf7e0ab2ad2d4dbdb {
  meta:
    description = "datamaliciousorder - file 20160311_0d2fea35881537dbf7e0ab2ad2d4dbdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbfd12f959df3cd446a0bac3957e35a18c27ab09c233a65f8d3a2b54866e34e2"

  strings:
    $s1  = "testContext = addBack[\"Exp\" + value + \"nvir\".check() + cssFn + \"tStr\" + rkeyEvent](\"%TEMP%\" + simulate) + \"qs\".check()" ascii
    $s2  = "testContext = addBack[\"Exp\" + value + \"nvir\".check() + cssFn + \"tStr\" + rkeyEvent](\"%TEMP%\" + simulate) + \"qs\".check()" ascii
    $s3  = "bulk[\"o\" + always + \"n\"](cacheLength + \"T\".check(), dataPriv + \"p:/\" + propName + \"litas.\" + clientTop + \"4t4h4\".che" ascii
    $s4  = "w((Math.pow(charCode, 2) - pointerleave), (2 + pipe)) - (15 & view)) + 3 * (statusText | 227))))));" fullword ascii
    $s5  = "tmlPrefilter)) * (1 + genFx) * (2 + pipe) | ((Math.pow((3 + hover), (2 & children)) - (3 + rnumnonpx)) & ((928 / siblings) - (14" ascii
    $s6  = "focusin[\"R\" + setDocument + \"n\"](testContext.check((5 * charCode * 3 * charCode - 23 * children)), ((17 | copy) - (Math.pow(" ascii
    $s7  = "children) - 150)), pipe);" fullword ascii
    $s8  = "57 / getClass)))) - (Math.pow(((3 * marginDiv & (1242 + removeProp)) / (Math.pow((8 + show), (1 * children)) - (800 | isHidden))" ascii
    $s9  = "_$ = \"WScri\", msFullscreenElement = \"e\", bindType = \"Create\", soFar = \"5\", rkeyEvent = \"ings\", cssFn = \"onmen\";" fullword ascii
    $s10 = "focusin[\"R\" + setDocument + \"n\"](testContext.check((5 * charCode * 3 * charCode - 23 * children)), ((17 | copy) - (Math.pow(" ascii
    $s11 = ", !(time < ((((22 / cssText) & (66 / maxIterations)) * ((37 - curValue) + (233, genFx)) * (17 * children * 2 * children, (36 / h" ascii
    $s12 = "bulk = getStyles[rhash + \"ipt\".check()][defaultValue + \"eOb\" + ct](\"MSX\" + parsed + \".XMLH\".check() + tokenCache);" fullword ascii
    $s13 = "addBack = slideToggle[bindType + \"Objec\" + handler](\"WSc\".check() + funcName + \"t.Shel\" + appendChild);" fullword ascii
    $s14 = "var pipe = 0," fullword ascii
    $s15 = "setOffset[\"ty\" + always] = (genFx * 1);" fullword ascii
    $s16 = "bulk[\"s\" + collection + \"d\"]();" fullword ascii
    $s17 = "filters[noGlobal + \"oFile\"](testContext, ((promise * 3 + file) / (931 / define)));" fullword ascii
    $s18 = "namespace[animate + \"ose\"]();" fullword ascii
    $s19 = "function holdReady() {" fullword ascii
    $s20 = "  return elem" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}