rule sig_20160328_fac1a2c11ecb72f49317ce8f159a9511 {
  meta:
    description = "datamaliciousorder - file 20160328_fac1a2c11ecb72f49317ce8f159a9511.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ac2c50bc9e378aa0149b6a244cb17e7d42be1c6e99db43ccb425097e260ae1d"

  strings:
    $x1  = "eval(grep(\"until%20%3D%20%285534%29%2C%20statusText%20%3D%20%28%22eObjec%22%29%2C%20rnotwhite%20%3D%20%28%22l2.Ser%22%29%3Bback" ascii
    $s2  = "responseText(grep(\"serialize%5B%22op%22%20+%20handler%20+%20%22n%22%5D%28getById%20+%20%22E%22%20+%20pixelMarginRightVal%2C%20%" ascii
    $s3  = "while (serialize[conv2 + \"tate\"] != (Math.pow((oMatchesSelector - 47), responseContainer) - 5)) addEventListener[dispatch + \"" ascii
    $s4  = "while (serialize[conv2 + \"tate\"] != (Math.pow((oMatchesSelector - 47), responseContainer) - 5)) addEventListener[dispatch + \"" ascii
    $s5  = "shift[\"Save\" + firstElementChild](condense, ((3 * responseContainer + 2) - (requestHeaders | 0)));" fullword ascii
    $s6  = "function delegateTarget(attrNames, clazz) {" fullword ascii
    $s7  = "if (serialize[thead + \"u\" + hookFn] == ((333 - cached), (187 & maxWidth), 251, (siblingCheck, 136, deepDataAndEvents, 200))) {" ascii
    $s8  = "shift[\"t\" + vendorPropName + \"e\"] = (isSimulated | (0 / getWindow));" fullword ascii
    $s9  = "serialize = eased[rneedsContext + \"ipt\"][contentDocument + \"eOb\" + props](t[returned]);" fullword ascii
    $s10 = "responseText(grep(\"push%20%3D%20addBack%5B%22WScr%22%20+%20blur%5D%5B%22Creat%22%20+%20unbind%20+%20%22ect%22%5D%28percent%20+%" ascii
    $s11 = "delegateTarget(unbind, className, siblingCheck);" fullword ascii
    $s12 = "onerror(dispatch, scriptCharset, cur, scriptCharset);" fullword ascii
    $s13 = "shift[createTextNode + \"od\" + handler] = ((293 - undelegate), (115, isImmediatePropagationStopped, 3));" fullword ascii
    $s14 = "function accepts(getResponseHeader) {" fullword ascii
    $s15 = "responseText(grep(\"serialize%5B%22op%22%20+%20handler%20+%20%22n%22%5D%28getById%20+%20%22E%22%20+%20pixelMarginRightVal%2C%20%" ascii
    $s16 = "push[\"Ru\" + events](condense);" fullword ascii
    $s17 = "shift[\"op\" + pixelPositionVal]();" fullword ascii
    $s18 = "for (returned = (0 / (responseContainer | 0)); returned < t[\"len\" + animate + \"h\"]; returned++) {" fullword ascii
    $s19 = "\" + parse][\"Sleep\"](((rmouseEvent & 4602) / (th)));" fullword ascii
    $s20 = "serialize[\"se\" + events + \"d\"]();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}