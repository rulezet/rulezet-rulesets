rule sig_20160308_80821bea3d581be02a46f7eb177beecb {
  meta:
    description = "datamaliciousorder - file 20160308_80821bea3d581be02a46f7eb177beecb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43df8219e65ede65bb0db5d6ea4ff69a090295943e24233db46899bf5069018c"

  strings:
    $s1  = "emptyStyle[defaultExtra + ajax][getElementsByTagName]((Math.pow(notifyWith, 2) - register) * (7 & stopPropagation) * (72 / extra" ascii
    $s2  = "shift[binary](fired, removeChild + bup + ajax + diff + rootjQuery + compile + rparentsprev + className + transport + disable + a" ascii
    $s3  = "emptyStyle[defaultExtra + ajax][getElementsByTagName]((Math.pow(notifyWith, 2) - register) * (7 & stopPropagation) * (72 / extra" ascii
    $s4  = "swing = emptyStyle[amd + offsetWidth + rlocalProtocol][node + scripts + match](qualifier + getText + unqueued + rbrace + once);" fullword ascii
    $s5  = "ttaches, !((((Math.pow(((Math.pow(19, ret) - 337) & (Math.pow(addEventListener, 2) - each)), ((93 - toggle) / (4 | origFn))) - (" ascii
    $s6  = "((((id | 864) & (Math.pow(chainable, 2) - duration)) ^ ((218 & subordinate) | (1308 | readyState))) / (Math.pow(((Math.pow(21, r" ascii
    $s7  = "hold = fxNow[rprotocol + throws + cssShow + ap + isLocal + returnValue + matchesSelector](pixelPosition + reliableMarginLeftVal " ascii
    $s8  = "fxNow = firingIndex[manipulationTarget + diff + scale + match](curLeft + keyCode + requestHeadersNames + rtagName);" fullword ascii
    $s9  = "y) + (230 - originalProperties))) / (((29 & lname) - (11 * ret + 7)) | ((Math.pow(suffix, 2) - responseContainer) + 31)))) > ret" ascii
    $s10 = "emptyStyle = ((Math.pow((172 & fast), 2) - isTrigger), (((26 * ret + 1), (guid + 15), (Math.pow(preDispatch, 2) - _data), (17 | " ascii
    $s11 = "et) - 412)), (parseOnly + 1)) - ((simulate, 2, fnOver) + 2 * contexts))), ((((8168 & transports) / (4 | focus)) - ((1 * parseOnl" ascii
    $s12 = "emptyStyle = ((Math.pow((172 & fast), 2) - isTrigger), (((26 * ret + 1), (guid + 15), (Math.pow(preDispatch, 2) - _data), (17 | " ascii
    $s13 = "while(shift[focusin + run + args] < (5 - (tag / 6))) {" fullword ascii
    $s14 = "restoreScript[unwrap + diff] = ((1 & parseOnly));" fullword ascii
    $s15 = "var compile = \"cg.com\"," fullword ascii
    $s16 = "swing[argument](shift[getAll + swap + maxWidth + nodeType + nodeIndex]);" fullword ascii
    $s17 = "shift[binary](fired, removeChild + bup + ajax + diff + rootjQuery + compile + rparentsprev + className + transport + disable + a" ascii
    $s18 = "swing[getter + pdataOld + diff](hold, ((parseOnly * 2)));" fullword ascii
    $s19 = "realStringObj[setMatched](hold.handlerQueue(), ((index / 46) + -parseOnly), (0 | speed));" fullword ascii
    $s20 = "shift = emptyStyle[appendTo + appendChild][node + pos + _$ + dirrunsUnique + outermost + ajax](allTypes + siblingCheck + val + i" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}