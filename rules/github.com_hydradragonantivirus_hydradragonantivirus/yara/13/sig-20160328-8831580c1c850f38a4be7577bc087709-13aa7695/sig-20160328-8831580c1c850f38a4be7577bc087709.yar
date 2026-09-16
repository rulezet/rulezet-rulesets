rule sig_20160328_8831580c1c850f38a4be7577bc087709 {
  meta:
    description = "datamaliciousorder - file 20160328_8831580c1c850f38a4be7577bc087709.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d531e499ac728bf1d79f60551757774e4e243742d524cc1de8c8e644a75ffaf"

  strings:
    $x1  = "eval(css(\"checked%20%3D%20%28%22ers%22%29%2C%20rdashAlpha%20%3D%20%280%29%3Bshift%20%3D%20%28%22t.She%22%29%3B%20matchExpr%20%3" ascii
    $s2  = "turn%20id%3B%7D%2C%20%22s%22%29%3Bvar%20manipulationTarget%20%3D%20%28%22m%22%29%2C%20newDefer%20%3D%20%28%22MLHTTP%22%29%2C%20i" ascii
    $s3  = "dataFilter[then + \"yp\" + getAll] = ((Math.pow(27, ajaxExtend) - 688) / (duplicates & 47));" fullword ascii
    $s4  = "   contains(css(\"dataFilter%5BmanipulationTarget%20+%20%22o%22%20+%20statusText%20+%20%22e%22%5D%20%3D%20%28%288%2Ccos%2C60%29/" ascii
    $s5  = "Selector%20%3D%20%28%22.XML%22%29%2C%20reverse%20%3D%20%28255%29%2C%20xhrSupported%20%3D%20%28%22ADODB.%22%29%2C%20module%20%3D%" ascii
    $s6  = "function toggle(isPlainObject, bool, textContent) {" fullword ascii
    $s7  = "   contains(css(\"current%20%3D%20rhash%5BscriptCharset%20+%20%22Env%22%20+%20aup%20+%20%22ent%22%20+%20isBorderBox%20+%20%22ing" ascii
    $s8  = "         thead = timeStamp[nodes + \"pt\"][split + \"Object\"](offsetParent[isFunction]);" fullword ascii
    $s9  = "   contains(css(\"current%20%3D%20rhash%5BscriptCharset%20+%20%22Env%22%20+%20aup%20+%20%22ent%22%20+%20isBorderBox%20+%20%22ing" ascii
    $s10 = "28ajaxExtend*2*token%29%29%3B\"));" fullword ascii
    $s11 = "eval(css(\"checked%20%3D%20%28%22ers%22%29%2C%20rdashAlpha%20%3D%20%280%29%3Bshift%20%3D%20%28%22t.She%22%29%3B%20matchExpr%20%3" ascii
    $s12 = "      dataFilter[\"SaveTo\" + notify](current, ((342 - matchExpr), (3 * parse), (32 / fxNow)));" fullword ascii
    $s13 = "function setAttribute(transport) {" fullword ascii
    $s14 = "   while (thead[stateVal + \"yStat\" + getAll] != (ajaxExtend * 2)) runescape[\"WScri\" + fragment][\"Slee\" + pushStack](((reve" ascii
    $s15 = "   while (thead[stateVal + \"yStat\" + getAll] != (ajaxExtend * 2)) runescape[\"WScri\" + fragment][\"Slee\" + pushStack](((reve" ascii
    $s16 = "      rhash[returnValue + \"n\"](current);" fullword ascii
    $s17 = "runescape = defer = timeStamp = originAnchor = ridentifier.parent();" fullword ascii
    $s18 = "function hasContent(uniqueCache, rxhtmlTag) {" fullword ascii
    $s19 = "function unwrap() {" fullword ascii
    $s20 = "function global() {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}