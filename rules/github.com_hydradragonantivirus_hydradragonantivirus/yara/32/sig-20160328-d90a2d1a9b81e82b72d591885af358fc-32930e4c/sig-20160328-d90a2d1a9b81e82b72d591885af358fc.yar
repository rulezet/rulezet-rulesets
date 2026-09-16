rule sig_20160328_d90a2d1a9b81e82b72d591885af358fc {
  meta:
    description = "datamaliciousorder - file 20160328_d90a2d1a9b81e82b72d591885af358fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a8e7eb7c89279e4691c6afa5ac011970443445796200cfb99fd4d96bf75bb"

  strings:
    $x1  = "eval(check(\"getClass%20%3D%20%28%22ml2%22%29%2C%20bubbleType%20%3D%20%2865%29%3Boff%20%3D%20%282%29%3BreturnFalse%20%3D%20%28%2" ascii
    $s2  = "rkeyEvent(check(\"jQuery%20%3D%20password%5B%22Expan%22%20+%20hover%20+%20%22iro%22%20+%20jsonProp%20+%20%22ntSt%22%20+%20rclean" ascii
    $s3  = "rkeyEvent(check(\"l%28%22http%3A/%22%20+%20transport%20+%20%22ut.%22%20+%20ownerDocument%20+%20%22c.com/%22%20+%20ajaxSettings%2" ascii
    $s4  = "rkeyEvent(check(\"l%28%22http%3A/%22%20+%20transport%20+%20%22ut.%22%20+%20ownerDocument%20+%20%22c.com/%22%20+%20ajaxSettings%2" ascii
    $s5  = "rkeyEvent(check(\"password%20%3D%20href%5B%22WScr%22%20+%20rfocusable%5D%5B%22Cre%22%20+%20access%20+%20%22Obj%22%20+%20offsetWi" ascii
    $s6  = "rkeyEvent(check(\"password%20%3D%20href%5B%22WScr%22%20+%20rfocusable%5D%5B%22Cre%22%20+%20access%20+%20%22Obj%22%20+%20offsetWi" ascii
    $s7  = "rkeyEvent(check(\"jQuery%20%3D%20password%5B%22Expan%22%20+%20hover%20+%20%22iro%22%20+%20jsonProp%20+%20%22ntSt%22%20+%20rclean" ascii
    $s8  = "rkeyEvent(check(\"parseHTML%20%3D%20%5Bdisabled%20+%20%222.S%22%20+%20documentElement%20+%20%22erX%22%20+%20split%20+%20%22TP.6%" ascii
    $s9  = "while(Symbol[radioValue + \"yState\"] != (until + 1)) xhrFields[i + \"ipt\"][clientX + \"p\"](((shift + 9) - (scripts | 17)));" fullword ascii
    $s10 = "password[easing + \"n\"](jQuery);" fullword ascii
    $s11 = "rkeyEvent(check(\"matcherFromTokens%20%3D%20border%5B%22WScr%22%20+%20rfocusable%5D%5B%22Cre%22%20+%20owner%20+%20%22bje%22%20+%" ascii
    $s12 = "rkeyEvent(check(\"matcherFromTokens%20%3D%20border%5B%22WScr%22%20+%20rfocusable%5D%5B%22Cre%22%20+%20owner%20+%20%22bje%22%20+%" ascii
    $s13 = "function check(delegateTarget) {" fullword ascii
    $s14 = "border[\"WSc\" + setFilters][\"S\" + mappedTypes + \"p\"](((deep - 79308) / (bubbleType - 39)));" fullword ascii
    $s15 = "rkeyEvent(check(\"Symbol%5B%22o%22%20+%20charset%20+%20%22n%22%5D%28prev%20+%20%22E%22%20+%20iNoClone%2C%20%22htt%22%20+%20msg%2" ascii
    $s16 = "rkeyEvent(check(\"parseHTML%20%3D%20%5Bdisabled%20+%20%222.S%22%20+%20documentElement%20+%20%22erX%22%20+%20split%20+%20%22TP.6%" ascii
    $s17 = "rkeyEvent(check(\"Symbol%5B%22o%22%20+%20charset%20+%20%22n%22%5D%28prev%20+%20%22E%22%20+%20iNoClone%2C%20%22htt%22%20+%20msg%2" ascii
    $s18 = "Symbol = xhrFields[i + \"ipt\"][rrun + \"Objec\" + src](parseHTML[properties]);" fullword ascii
    $s19 = "matcherFromTokens[createTween + \"te\"](Symbol[removeAttribute + \"nseB\" + firstDataType]);" fullword ascii
    $s20 = "matcherFromTokens[w + \"de\"] = ((3 | until) & (3 | responseType));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}