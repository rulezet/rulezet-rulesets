rule sig_20160325_f9a5dd6dfdeb16a334a7e52e2b647fcf {
  meta:
    description = "datamaliciousorder - file 20160325_f9a5dd6dfdeb16a334a7e52e2b647fcf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33572ac7ddf692f690e4e4f755caa2449dfba9a340e47a4f682b9f6c070d090e"

  strings:
    $s1  = "matchedCount = \"os.com\", completed = (function vendorPropName._removeData() {" fullword ascii
    $s2  = "function contents(global, holdReady, bulk, sortDetached) {" fullword ascii
    $s3  = "originalEvent[\"S\" + optionSet + \"eep\"](((19968 / completed) | (1881 * seed + 1110)));" fullword ascii
    $s4  = "eval(overflow(\"contents%28text%2C%20tweeners%2C%20%28replaceAll/26%29%2C%20method%20+%20%22eToF%22%20+%20fadeToggle%29%3B\"));" fullword ascii
    $s5  = "pointerleave[outermost + \"se\"]();" fullword ascii
    $s6  = "var func = [][\"constr\" + type][\"protot\" + writable][\"s\" + cssFn + \"t\"][defaultDisplay]();" fullword ascii
    $s7  = "tweeners[\"ty\" + createPseudo] = (disable | 1);" fullword ascii
    $s8  = "eval(overflow(\"marginDiv%5B%22op%22%20+%20fx%20+%20%22n%22%5D%28timeoutTimer%20+%20%22ET%22%2C%20onreadystatechange%20+%20%22%3" ascii
    $s9  = "return holdReady[sortDetached](global, bulk);" fullword ascii
    $s10 = "copyIsArray(props, tokenize, origType, click);" fullword ascii
    $s11 = "eval(overflow(\"addEventListener%5Btag%20+%20%22u%22%20+%20createTween%5D%28text%29%3B\"));" fullword ascii
    $s12 = "eval(overflow(\"marginDiv%5B%22op%22%20+%20fx%20+%20%22n%22%5D%28timeoutTimer%20+%20%22ET%22%2C%20onreadystatechange%20+%20%22%3" ascii
    $s13 = "isFunction(settings, props, completed, matchContext);" fullword ascii
    $s14 = "outermost = \"clo\";" fullword ascii
    $s15 = "function unwrap() {" fullword ascii
    $s16 = "function isEmptyObject() {" fullword ascii
    $s17 = "function responseContainer() {" fullword ascii
    $s18 = "var method = \"sav\"," fullword ascii
    $s19 = "function srcElements() {" fullword ascii
    $s20 = "function pixelPosition() {" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}