rule sig_20160311_01284d18e603522cc8bdabed57583bb3 {
  meta:
    description = "datamaliciousorder - file 20160311_01284d18e603522cc8bdabed57583bb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4657dd42ac4aa73a1db716ebea1ef19734fcc236732b6d573b8ba78ebf65f406"

  strings:
    $s1  = "host[\"op\" + list + \"n\"](rtypenamespace + \"ET\".chainable(), opener + \"p:/\" + elemData + \".gov.\" + width + \"35y\".chain" ascii
    $s2  = "5))), ((focusin, 244, fadeIn) - (3 & head))) * (((5 * head * 2 * rsingleTag | (156 & rmargin)) / ((48 | rmsPrefix) - 13)) - (((i" ascii
    $s3  = " !((((((1 | padding) | (41 - matchers)) + ((64 | padding), 3 * fadeIn * 3 * rneedsContext, (208, orig), (Math.pow(13, head) - 14" ascii
    $s4  = "completed[\"R\".chainable() + backgroundClip + \"n\"](speed.chainable(((matchers | 68), (Math.pow(addBack, 2) - initialInUnit), " ascii
    $s5  = "* rneedsContext + 4))), ((qsa - 5) * (rmouseEvent, 230, padding)), ((46 - num) | (0 / siblings)));" fullword ascii
    $s6  = "host[\"op\" + list + \"n\"](rtypenamespace + \"ET\".chainable(), opener + \"p:/\" + elemData + \".gov.\" + width + \"35y\".chain" ascii
    $s7  = "speed = statusText[clientTop + \"Enviro\".chainable() + tmp + \"tStr\" + inspected](\"%TEMP\" + boxSizingReliableVal) + \"the\"." ascii
    $s8  = "speed = statusText[clientTop + \"Enviro\".chainable() + tmp + \"tStr\" + inspected](\"%TEMP\" + boxSizingReliableVal) + \"the\"." ascii
    $s9  = "host = tuples[e + \"ipt\".chainable()][runescape + \"teOb\" + settings + \"t\"](pixelMarginRightVal + \"L2.XML\".chainable() + c" ascii
    $s10 = "tuples = (((67 & getResponseHeader) | (880 / curPosition)), (252 / (mouseenter * 3 + fadeIn)), eval(\"t\" + _load + \"i\".chaina" ascii
    $s11 = "host[\"se\" + disconnectedMatch + \"d\"]();" fullword ascii
    $s12 = "head = 2;" fullword ascii
    $s13 = "content();" fullword ascii
    $s14 = "function content() {" fullword ascii
    $s15 = "e() + marginRight + \".\" + method + \"cr\";" fullword ascii
    $s16 = "options = tuples[current + \"t\".chainable()][timeout + \"eObjec\" + setup](\"ADO\" + clearTimeout + \"Stre\".chainable() + cssN" ascii
    $s17 = "subtract = tuples[\"WScrip\" + setup];" fullword ascii
    $s18 = ") + method));" fullword ascii
    $s19 = "id[setup + \"yp\".chainable() + list] = ((2 * fadeIn) / (217, qsa));" fullword ascii
    $s20 = "options[\"save\" + timeStamp + \"e\".chainable()](speed, (2 + padding));" fullword ascii

  condition:
    uint16(0) == 0x6f72 and
    8 of them
}