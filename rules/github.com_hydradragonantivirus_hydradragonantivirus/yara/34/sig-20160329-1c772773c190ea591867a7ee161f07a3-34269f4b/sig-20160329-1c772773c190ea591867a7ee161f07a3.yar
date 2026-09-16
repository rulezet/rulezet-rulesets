rule sig_20160329_1c772773c190ea591867a7ee161f07a3 {
  meta:
    description = "datamaliciousorder - file 20160329_1c772773c190ea591867a7ee161f07a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1670b359f613d58ea322c613e3ce3582670de7f493cd365c0310a67aec0649cc"

  strings:
    $s1  = "content[slideDown + \"y\" + lastChild + \"e\"] = ((removeAttr | 20) - (Math.pow(div, 2) - postMap));" fullword ascii
    $s2  = "      content[replaceChild + \"e\" + getScript]();" fullword ascii
    $s3  = "   splice(\"removeClass%20%3D%20hasCompare%5B%22Exp%22%20+%20newSelector%20+%20%22iro%22%20+%20string%20+%20%22tStrin%22%20+%20c" ascii
    $s4  = "hasOwn(manipulationTarget, reset);" fullword ascii
    $s5  = "content[\"m\" + responses + \"e\"] = (3);" fullword ascii
    $s6  = "   splice(\"ifModified%20%3D%20%5Bimplementation%20+%20%22l2.Se%22%20+%20msMatchesSelector%20+%20%22LHTTP%22%20+%20handlerQueue%" ascii
    $s7  = "   splice(\"matchExpr%5BisArray%20+%20%22p%22%20+%20statusCode%5D%28%22G%22%20+%20slow%2C%20%22http%3A/%22%20+%20contentDocument" ascii
    $s8  = "function insertAfter(rfxtypes, temp, setMatched) {" fullword ascii
    $s9  = "   splice(\"code%28jQuery%20+%20%22%3A//my%22%20+%20delegateTarget%20+%20%22obil.c%22%20+%20arg%20+%20%22/h9%22%20+%20risSimple%" ascii
    $s10 = "   splice(\"code%28jQuery%20+%20%22%3A//my%22%20+%20delegateTarget%20+%20%22obil.c%22%20+%20arg%20+%20%22/h9%22%20+%20risSimple%" ascii
    $s11 = "      content[\"Writ\" + msFullscreenElement](matchExpr[\"res\" + rcssNum + \"Body\"]);" fullword ascii
    $s12 = "   splice(\"matchExpr%5BisArray%20+%20%22p%22%20+%20statusCode%5D%28%22G%22%20+%20slow%2C%20%22http%3A/%22%20+%20contentDocument" ascii
    $s13 = "      content[nidselect + \"oFi\" + prev](removeClass, ((defineProperty * 2) | configurable));" fullword ascii
    $s14 = "function username(rbracket) {" fullword ascii
    $s15 = "function bind(pageY, responseContainer) {" fullword ascii
    $s16 = "insertAfter(version, handlerQueue);" fullword ascii
    $s17 = "function hasOwn(j, createHTMLDocument, tokens) {" fullword ascii
    $s18 = "bind(pos);" fullword ascii
    $s19 = "function open(unmatched, compareDocumentPosition) {" fullword ascii
    $s20 = "camel = classCache = charset = rclass = matcher.getter();" fullword ascii

  condition:
    uint16(0) == 0x6e6f and
    8 of them
}