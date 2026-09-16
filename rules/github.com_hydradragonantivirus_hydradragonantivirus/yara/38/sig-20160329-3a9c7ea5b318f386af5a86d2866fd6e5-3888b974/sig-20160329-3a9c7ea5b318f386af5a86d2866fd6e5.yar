rule sig_20160329_3a9c7ea5b318f386af5a86d2866fd6e5 {
  meta:
    description = "datamaliciousorder - file 20160329_3a9c7ea5b318f386af5a86d2866fd6e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e471ee6e96381231569236c5ec46d7e6feead1a5e9dbfff5e18ef64026f225a"

  strings:
    $s1  = "if(w[addGetHookIf + \"tatus\"] == ((141, transport, 1) * (Math.pow(rejectWith, 2) - guaranteedUnique))) {" fullword ascii
    $s2  = "uniqueID(\"uniqueSort%5B%22WScri%22%20+%20push%5D%5B%22S%22%20+%20rsubmitterTypes%20+%20%22p%22%5D%28%28%282*identifier*13%29*%2" ascii
    $s3  = "uniqueID(\"while%20%28w%5B%22ready%22%20+%20head%20+%20%22e%22%5D%20%21%3D%20%28%28rmsPrefix*4+timeout%29%2C%284%7Ctimeout%29%29" ascii
    $s4  = "uniqueID(\"while%20%28w%5B%22ready%22%20+%20head%20+%20%22e%22%5D%20%21%3D%20%28%28rmsPrefix*4+timeout%29%2C%284%7Ctimeout%29%29" ascii
    $s5  = "documentElement(optSelected, getResponseHeader, head, curOffset, register);" fullword ascii
    $s6  = "uniqueID(\"notify%20%3D%20slideToggle%5BgetResponseHeader%20+%20%22t%22%5D%5BisDefaultPrevented%20+%20%22ateObj%22%20+%20body%5D" ascii
    $s7  = "uniqueID(\"notify%20%3D%20slideToggle%5BgetResponseHeader%20+%20%22t%22%5D%5BisDefaultPrevented%20+%20%22ateObj%22%20+%20body%5D" ascii
    $s8  = "notify[dataFilter + \"e\" + matchExpr]();" fullword ascii
    $s9  = "notify[\"ty\" + seed + \"e\"] = ((1 & rdashAlpha) & (1 | curCSS));" fullword ascii
    $s10 = "for(Deferred = (1 * curCSS); Deferred < offsetWidth[speeds + \"gth\"]; Deferred++) {" fullword ascii
    $s11 = "notify[\"Write\"](w[cssText + \"nseBo\" + arg]);" fullword ascii
    $s12 = "uniqueID(\"uniqueSort%5B%22WScri%22%20+%20push%5D%5B%22S%22%20+%20rsubmitterTypes%20+%20%22p%22%5D%28%28%282*identifier*13%29*%2" ascii
    $s13 = "function beforeSend(noCloneChecked, to, run) {" fullword ascii
    $s14 = "function byElement() {" fullword ascii
    $s15 = "function nType() {" fullword ascii
    $s16 = "function animate() {" fullword ascii
    $s17 = "nType(traditional, timeoutTimer, isXMLDoc);" fullword ascii
    $s18 = "uniqueID(\"notify%5BrnoInnerhtml%20+%20%22ToF%22%20+%20defineProperty%5D%28rjsonp%2C%20%28%28rdashAlpha+0%29+%28rdashAlpha*1%29%" ascii
    $s19 = "beforeSend(easing, optSelected);" fullword ascii
    $s20 = "function parents(excess, augmentWidthOrHeight) {" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}