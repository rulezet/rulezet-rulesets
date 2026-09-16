rule sig_20160311_f74a72301da9705ea74dae5a2f1a9e01 {
  meta:
    description = "datamaliciousorder - file 20160311_f74a72301da9705ea74dae5a2f1a9e01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "683c59de2fe174f1144da8a6324f479c477778f505bf0bddc2f7407e3d5d2319"

  strings:
    $s1  = "processData = compilerCache[keepScripts + \"pt\"][nonce + \"ateO\".toArray() + first + \"ct\"](ownerDocument + \"B.Str\" + fixIn" ascii
    $s2  = "charCode[rhash + \"yp\" + getResponseHeader] = ((isEmptyObject / 11) - sibling);" fullword ascii
    $s3  = "hasClass = ajaxTransport[marginRight + \"Env\" + getBoundingClientRect + \"mentS\".toArray() + getAll](\"%TEMP\" + percent) + \"" ascii
    $s4  = "hasClass = ajaxTransport[marginRight + \"Env\" + getBoundingClientRect + \"mentS\".toArray() + getAll](\"%TEMP\" + percent) + \"" ascii
    $s5  = "last + \".\".toArray() + addGetHookIf + \"r\";" fullword ascii
    $s6  = "firstElementChild[\"op\".toArray() + getResponseHeader + \"n\"](insertBefore + \"T\", eventHandle + \"//pete\".toArray() + check" ascii
    $s7  = "ajaxTransport = actualDisplay[tuple + \"eObje\" + clone](\"WScri\".toArray() + letterSpacing + \"ll\");" fullword ascii
    $s8  = "em.\" + _default + \"8774\" + inArray, !((((trim | 3) & trim) & ((33 & startLength) / (2 + timeout))) == 3));" fullword ascii
    $s9  = "isXML[\"c\" + abort + \"e\".toArray()]();" fullword ascii
    $s10 = " | (sibling / 22)), ((clearCloneStyle & 223), (selectedIndex * 3 + multipleContexts), (0 | sibling)));" fullword ascii
    $s11 = "firstElementChild = compilerCache[letter + \"ipt\"][nonce + \"ateO\".toArray() + old](\"MSX\" + styles + \"XMLHTT\" + ajax);" fullword ascii
    $s12 = "percent = \"%/\";" fullword ascii
    $s13 = "protocol();" fullword ascii
    $s14 = "function protocol() {" fullword ascii
    $s15 = "function createElement() {" fullword ascii
    $s16 = "function rpseudo() {" fullword ascii
    $s17 = "abort = \"los\";" fullword ascii
    $s18 = "defineProperty[\"Ru\" + _data](hasClass.toArray(((360 / settings), (19 * multipleContexts + 13))), ((matcherFromGroupMatchers * " ascii
    $s19 = "var sibling = 0;" fullword ascii
    $s20 = "function parents() {" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}