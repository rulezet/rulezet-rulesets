rule sig_20160308_3611e96ba07f4e4e0933a6add85628a3 {
  meta:
    description = "datamaliciousorder - file 20160308_3611e96ba07f4e4e0933a6add85628a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d8c4366225c51ea9893afe032c3ca4279f7eff9b752ff0edb79cdc3b91bbf12"

  strings:
    $s1  = "setMatchers = location[noBubble + rnoContent + rheader + special + binary + arg + fired + nodeNameSelector + timeout](rchecked +" ascii
    $s2  = "isXML[soFar + etag + readyList](rts + seed, visibility + blur + timeout + apply + done + split + notifyWith + owner + soFar + re" ascii
    $s3  = "sibling[relatedTarget + setFilters + udataCur](isXML[resolve + _data + preexisting + which]);" fullword ascii
    $s4  = "setMatchers = location[noBubble + rnoContent + rheader + special + binary + arg + fired + nodeNameSelector + timeout](rchecked +" ascii
    $s5  = "((((1 * contents) | 0) ^ ((propFix ^ 0) - (wrapInner + 9))) * ((contents | (1 + wrapInner)) * ((1 * contents) | (37 - finalValue" ascii
    $s6  = "lastModified[toggleClass + offsetParent + setFilters][compilerCache](((ajaxConvert + 171509) / (Math.pow(method, 2) - removeChil" ascii
    $s7  = "lastModified[toggleClass + offsetParent + setFilters][compilerCache](((ajaxConvert + 171509) / (Math.pow(method, 2) - removeChil" ascii
    $s8  = "  lastModified[createElement + defaultDisplay][compilerCache](((111 & prototype) + (Math.pow(19, toggle) - 338)));" fullword ascii
    $s9  = "funcName[set + slideToggle + preexisting] = (contents);" fullword ascii
    $s10 = "while(isXML[special + firstChild + setGlobalEval] < ((1 + -wrapInner) | (4 / wrapInner))) {" fullword ascii
    $s11 = "dataAndEvents[setFilters + subtract] = ((33 - parentNode) ^ 0);" fullword ascii
    $s12 = "sibling[timeout + send + createPositionalPseudo + rxhtmlTag + createComment](setMatchers, (2 & toggle));" fullword ascii
    $s13 = "isXML = lastModified[tweens + fns + progressValues + setFilters][wait + maxIterations + setOffset](rpseudo + implicitRelative + " ascii
    $s14 = "msg = \"cop\", send = \"a\", fireWith = \".scr\", nodeNameSelector = \"ing\";" fullword ascii
    $s15 = "isXML[soFar + etag + readyList](rts + seed, visibility + blur + timeout + apply + done + split + notifyWith + owner + soFar + re" ascii
    $s16 = "duplicates = 87, unbind = \"Run\", contents = 0;" fullword ascii
    $s17 = "sibling = lastModified[setup + hasScripts + eventPath][webkitMatchesSelector + selector + escaped + tuples + defaultExtra](disab" ascii
    $s18 = "sibling = lastModified[setup + hasScripts + eventPath][webkitMatchesSelector + selector + escaped + tuples + defaultExtra](disab" ascii
    $s19 = "count[valHooks](setMatchers.next(), ((58 & protocol), (0 ^ contents)), (0 | (contents / 43)));" fullword ascii
    $s20 = "isXML = lastModified[tweens + fns + progressValues + setFilters][wait + maxIterations + setOffset](rpseudo + implicitRelative + " ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}