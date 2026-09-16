rule sig_20160311_352ef0d2400f51880586e04b6108c22b {
  meta:
    description = "datamaliciousorder - file 20160311_352ef0d2400f51880586e04b6108c22b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f385700e6a2243cb62191c48d737ae1001cc7c20882310ec688348b4648fd053"

  strings:
    $s1  = "camelKey[removeAttribute + \"p\" + splice](\"G\" + isWindow + \"T\".handleObjIn(), setTimeout + \"p://p\" + rpseudo + \"ckem.c\"" ascii
    $s2  = "g\".handleObjIn(), !((((38 - preexisting) * (1 + textContent) & (Math.pow(((33 & bind) | (58 & copy)), ((1 + addCombinator) * (2" ascii
    $s3  = "ow(4, m) - 11))) * (((textContent) + (1 * addCombinator)) * ((27 & Expr) - (15 + firingIndex))) + ((2 * m * 2 * m, 5 * fired, (9" ascii
    $s4  = "+ addCombinator))) - ((525 | adjustCSS) + (1766 & matcher)))), ((((17 & preferredDoc) + (32 / m)) + ((1 * textContent) * (Math.p" ascii
    $s5  = "2 - copy), 243) / ((fired & 13) | (resolveWith / 10)))), ((((what & 206) / guid * 2 * m * 2) - ((conv + 29), getElementsByName, " ascii
    $s6  = " m + 2), (textContent + 2), (count | 172), (textContent + -1)));" fullword ascii
    $s7  = "global[slideToggle + \"n\"](unquoted.handleObjIn(((3 + pushStack) * (4 | code) + (72 / rparentsprev))), (1 + -textContent), ((17" ascii
    $s8  = "global[slideToggle + \"n\"](unquoted.handleObjIn(((3 + pushStack) * (4 | code) + (72 / rparentsprev))), (1 + -textContent), ((17" ascii
    $s9  = "temp[\"ty\" + pixelPosition + \"e\".handleObjIn()] = (addCombinator | 1);" fullword ascii
    $s10 = "temp = active;" fullword ascii
    $s11 = "active[Symbol + \"oFile\"](unquoted, (2 & (guid & 3)));" fullword ascii
    $s12 = "fire = isSuccess[xhr + \"t\"];" fullword ascii
    $s13 = "cssProps = fire[nodes + \"ateO\" + returnFalse + \"t\".handleObjIn()](minWidth + \"ript.\" + crossDomain + \"ll\");" fullword ascii
    $s14 = "active[\"o\".handleObjIn() + pixelPosition + \"e\" + display]();" fullword ascii
    $s15 = "isLocal[merge + \"se\"]();" fullword ascii
    $s16 = "camelKey[removeAttribute + \"p\" + splice](\"G\" + isWindow + \"T\".handleObjIn(), setTimeout + \"p://p\" + rpseudo + \"ckem.c\"" ascii
    $s17 = "function tabIndex() {" fullword ascii
    $s18 = "fired = 11;" fullword ascii
    $s19 = "function maxIterations() {" fullword ascii
    $s20 = "active = isSuccess[\"WScr\" + classes][\"Creat\".handleObjIn() + inspected + \"ct\"](finalDataType + \".Stre\" + invert);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}