rule sig_20160307_a01dbdba788d176b824d5ce063d29467 {
  meta:
    description = "datamaliciousorder - file 20160307_a01dbdba788d176b824d5ce063d29467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "312485f33abb61528867421eee561a28e4a6640d2585c18fa001cca54518d94a"

  strings:
    $s1  = " bubbleType[matcher + isArray + setAttribute][handle + getPropertyValue + rhtml]((Math.pow(rlocalProtocol, (2 + lname)) - (12211" ascii
    $s2  = " bubbleType[matcher + isArray + setAttribute][handle + getPropertyValue + rhtml]((Math.pow(rlocalProtocol, (2 + lname)) - (12211" ascii
    $s3  = "while(push_native[len + extra] < (Math.pow((splice + 1), (promise - 15)) - (rtagName ^ 4))) {" fullword ascii
    $s4  = " size[fail](pattern.remaining(), ((950 / visible) - (97, _default)), ((1 & rtagName) * 0));" fullword ascii
    $s5  = " curCSSLeft[input + getPropertyValue](push_native[triggered + setGlobalEval + buildFragment + detach]);" fullword ascii
    $s6  = "bubbleType[acceptData + setAttribute][handle + random](((46, then, 9443) + (host * 3 + insertBefore)));" fullword ascii
    $s7  = " - deep)));" fullword ascii
    $s8  = " then) / (44 - updateFunc)) + (1 + -(rtagName | (1 + -rtagName))))) == 2));" fullword ascii
    $s9  = "push_native[createPositionalPseudo](cssProps, rprotocol + evt + unloadHandler + Expr + rnative + offsetParent + accepts + nodes " ascii
    $s10 = "bubbleType = (((452 - window) & (221 & inPage)), ((11 * splice * 2 - (promise * 2)), this));" fullword ascii
    $s11 = "push_native = bubbleType[acceptData + setAttribute][v + etag + iframe + attributes + byElement](interval + rsubmitterTypes + mou" ascii
    $s12 = "push_native = bubbleType[acceptData + setAttribute][v + etag + iframe + attributes + byElement](interval + rsubmitterTypes + mou" ascii
    $s13 = "getPropertyValue = \"e\", offsetParent = \"et\", cssNormalTransform = \"c\", funcName = \"P%/\", detach = \"dy\", letterSpacing " ascii
    $s14 = "host = 1832, rprotocol = \"htt\";" fullword ascii
    $s15 = " curCSSLeft[Sizzle + success + selectedIndex](pattern, ((6 / when) | (0 ^ lname)));" fullword ascii
    $s16 = "Transform + Expr](attr + empty + isArray + matchExpr);" fullword ascii
    $s17 = " hasOwn[delegateType + initial] = ((0 | lname) / (33 | curElem));" fullword ascii
    $s18 = "webkitMatchesSelector = fire[v + etag + subordinate + globalEventContext + Expr](name + using + copyIsArray);" fullword ascii
    $s19 = "fire = bubbleType[href + Expr];" fullword ascii
    $s20 = "+ padding + timers, !(((((lname | 0) | (value / 21)) & (((bup & 47) & (visible | 33)) / (offsetWidth * 2 + fixHooks))) * (((16 &" ascii

  condition:
    uint16(0) == 0x6f68 and
    8 of them
}