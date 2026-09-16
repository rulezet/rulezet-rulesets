rule sig_20160329_aa933c2dc23748e995d97b96e9d1e6c0 {
  meta:
    description = "datamaliciousorder - file 20160329_aa933c2dc23748e995d97b96e9d1e6c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2093aaadee8906f0e927f9bb666a567482f1ea451e353cd6b4abc6f85de95aa6"

  strings:
    $s1  = "for (second = (addEventListener / (80 / combinator)); second < host[xhrSupported + \"h\"]; second++) {" fullword ascii
    $s2  = "isPlainObject = preventDefault[init + \"ipt\"][responseText + \"teObj\" + rcheckableType](host[second]);" fullword ascii
    $s3  = "copyIsArray(\"host%20%3D%20%5Bextra%20+%20%222.Serv%22%20+%20padding%20+%20%22MLHTT%22%20+%20msMatchesSelector%2C%20%22Msxml%22%" ascii
    $s4  = "preferredDoc[eventPath + \"eToFi\" + expando](step, ((rtypenamespace - 21)));" fullword ascii
    $s5  = "base[\"WSc\" + current][\"Sleep\"](((nodeType - 755) - (preexisting, 245, uniqueSort)));" fullword ascii
    $s6  = "copyIsArray(\"host%20%3D%20%5Bextra%20+%20%222.Serv%22%20+%20padding%20+%20%22MLHTT%22%20+%20msMatchesSelector%2C%20%22Msxml%22%" ascii
    $s7  = "width(setRequestHeader, isSimulated, marginLeft);" fullword ascii
    $s8  = "attrHandle[remove + \"pt\"][s + \"p\"](((len & 4578) + (nodeValue / 45)));" fullword ascii
    $s9  = "function b(isImmediatePropagationStopped, iframe) {" fullword ascii
    $s10 = "pageYOffset(duration, s, combinator, prevUntil, handlerQueue);" fullword ascii
    $s11 = "copyIsArray(\"step%20%3D%20location%5BrnoInnerhtml%20+%20%22andE%22%20+%20firstDataType%20+%20%22ronmen%22%20+%20responseType%20" ascii
    $s12 = "function pageYOffset() {" fullword ascii
    $s13 = "function nodeIndex() {" fullword ascii
    $s14 = "lace(/~/g, '%')));" fullword ascii
    $s15 = "radio(nodeType, document, Data, duration, ret);" fullword ascii
    $s16 = "Queue%20+%20%22ript%22%20+%20fireWith%20+%20%22l%22%29%3B\");" fullword ascii
    $s17 = "clientX(ret, arr, pattern, firstDataType, matchers);" fullword ascii
    $s18 = "function clientX(curPosition, on, parseFromString) {" fullword ascii
    $s19 = "function radio(prepend, source) {" fullword ascii
    $s20 = "num(_jQuery, eventPath, eventPath, Sizzle, init);" fullword ascii

  condition:
    uint16(0) == 0x6166 and
    8 of them
}