rule sig_20160311_df7599ed9ac8b8c0107ca14e209b8940 {
  meta:
    description = "datamaliciousorder - file 20160311_df7599ed9ac8b8c0107ca14e209b8940.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b65eca54b64339a88afac3f3e0f9c81efcb0486b5045d6edc07dcd5b1eb9724"

  strings:
    $s1  = "verse | 1) * (select, 222, documentIsHTML)))) == ((((20 & curTop) / (1 * get)) & (Math.pow(4, documentIsHTML) - 9)) * (((Math.po" ascii
    $s2  = "Sizzle[rquickExpr + \"pe\" + ct](\"G\".preventDefault() + newCache, \"http\" + hookFn + \"28.211\" + cloneNode + \"dd0/8\".preve" ascii
    $s3  = "reatePseudo)) & ((Math.pow((34 | reverse), 2) - (timeoutTimer * 4 + fail)) + ((45 - parse) + 0))))));" fullword ascii
    $s4  = "operator[isFunction + \"n\".preventDefault()](rmargin.preventDefault(((divStyle) * (50 - createPseudo) + (0 | fnOver))), 0, ((re" ascii
    $s5  = "w(winnow, 2) - setter) - 87) - ((matches + 12) & (cssShow - 60))) / ((((reverse | 19) | (fnOver * 10 + get)) & (135, has, 122, c" ascii
    $s6  = "operator[isFunction + \"n\".preventDefault()](rmargin.preventDefault(((divStyle) * (50 - createPseudo) + (0 | fnOver))), 0, ((re" ascii
    $s7  = "removeChild = namespaces[wrapAll + \"ipt\"][getBoundingClientRect + \"ateObj\" + timeout](\"ADO\".preventDefault() + access + \"" ascii
    $s8  = "\"ableM\".preventDefault() + textContent + \"eft\" + preDispatch + \"s\" + n;" fullword ascii
    $s9  = "removeChild = namespaces[wrapAll + \"ipt\"][getBoundingClientRect + \"ateObj\" + timeout](\"ADO\".preventDefault() + access + \"" ascii
    $s10 = "rmargin = newSelector[\"Expand\" + cache + \"ronm\".preventDefault() + firstChild + \"rings\"](computeStyleTests + \"P%/\") + ac" ascii
    $s11 = "removeChild[dir + \"File\"](rmargin, ((fnOver + 1) - (handler / 13)));" fullword ascii
    $s12 = "fixHooks[\"ty\".preventDefault() + compare + \"e\"] = (preFilters * (177, related, 3, preFilters));" fullword ascii
    $s13 = "winnow = 145, timeout = \"ect\", camelCase = 168676394, targets = \"nseBod\";" fullword ascii
    $s14 = "operator = newSelector;" fullword ascii
    $s15 = "newSelector = preexisting[innerHTML + \"Obj\" + timeout](\"WScr\".preventDefault() + done + \"Shel\" + option);" fullword ascii
    $s16 = "Sizzle = namespaces[\"WScrip\".preventDefault() + preFilter][\"Create\" + clearQueue](\"MSXM\" + l + \"XML\".preventDefault() + " ascii
    $s17 = ") + filter + \"i76u5\" + context, !((((documentIsHTML + 0) | (preFilters * (1 * documentIsHTML))) + ((1 * (preFilters + 0)) + ((" ascii
    $s18 = "Sizzle[\"s\" + nodeValue + \"nd\".preventDefault()]();" fullword ascii
    $s19 = "Sizzle = namespaces[\"WScrip\".preventDefault() + preFilter][\"Create\" + clearQueue](\"MSXM\" + l + \"XML\".preventDefault() + " ascii
    $s20 = "function compareDocumentPosition() {" fullword ascii

  condition:
    uint16(0) == 0x7865 and
    8 of them
}