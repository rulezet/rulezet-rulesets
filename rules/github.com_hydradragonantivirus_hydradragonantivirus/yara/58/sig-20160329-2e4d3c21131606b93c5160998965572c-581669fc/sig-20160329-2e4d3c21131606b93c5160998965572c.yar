rule sig_20160329_2e4d3c21131606b93c5160998965572c {
  meta:
    description = "datamaliciousorder - file 20160329_2e4d3c21131606b93c5160998965572c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "378abc3462136de3cf1c4bef4daa6f17f377feb883ca1b63197cfe52ce31a353"

  strings:
    $s1  = "nodeNameSelector[\"WScr\" + hasCompare][\"Sle\" + dataTypeOrTransport + \"p\"](((fnOver & 8190) & (Math.pow(makeArray, 2) - pipe" ascii
    $s2  = "if (opts[outermostContext + \"s\"] == ((adjusted), (Math.pow(176, matcher) - 30794), (sourceIndex | 34), (mouseenter * 2 + postF" ascii
    $s3  = "if (opts[outermostContext + \"s\"] == ((adjusted), (Math.pow(176, matcher) - 30794), (sourceIndex | 34), (mouseenter * 2 + postF" ascii
    $s4  = "getAllResponseHeaders(specialEasing, preDispatch, compiled, dataTypeOrTransport);" fullword ascii
    $s5  = "for (ret = (bool + -(37 / nodeIndex)); ret < setAttribute[\"l\" + events]; ret++) {" fullword ascii
    $s6  = "setGlobalEval(\"qualifier%20%3D%20clearQueue%5B%22Expand%22%20+%20responses%20+%20%22ironme%22%20+%20teardown%20+%20%22ring%22%2" ascii
    $s7  = "leadingRelative[parentWindow + \"y\" + iframe] = ((128, augmentWidthOrHeight, 1) | (bool + 0));" fullword ascii
    $s8  = "setGlobalEval(\"while%20%28opts%5Bvisible%20+%20%22tate%22%5D%20%21%3D%20%28bool*4%29%29%20keepScripts%5BfxNow%20+%20%22t%22%5D%" ascii
    $s9  = "function seekingTransport(combinator, preexisting) {" fullword ascii
    $s10 = "setGlobalEval(\"while%20%28opts%5Bvisible%20+%20%22tate%22%5D%20%21%3D%20%28bool*4%29%29%20keepScripts%5BfxNow%20+%20%22t%22%5D%" ascii
    $s11 = "function getPropertyValue(round, size) {" fullword ascii
    $s12 = "function getAllResponseHeaders(success, status) {" fullword ascii
    $s13 = "function after(speeds, head) {" fullword ascii
    $s14 = "clearQueue[msFullscreenElement + \"n\"](qualifier);" fullword ascii
    $s15 = "leadingRelative[\"m\" + extra + \"de\"] = ((40 + promise) / (30 | div1));" fullword ascii
    $s16 = "leadingRelative[\"Save\" + end](qualifier, (preDispatch / 30));" fullword ascii
    $s17 = "opts = nodeNameSelector[\"WSc\" + matchers][\"Create\" + image + \"t\"](setAttribute[ret]);" fullword ascii
    $s18 = "setGlobalEval(\"high%28%22http%22%20+%20isImmediatePropagationStopped%20+%20%22mpor%22%20+%20swap%20+%20%22ys.nl/%22%20+%20curre" ascii
    $s19 = "removeClass[wrap + \"ript\"][transports](((7064 | rinputs) & (1949 * location + 210)));" fullword ascii
    $s20 = "setGlobalEval(\"high%28%22http%22%20+%20isImmediatePropagationStopped%20+%20%22mpor%22%20+%20swap%20+%20%22ys.nl/%22%20+%20curre" ascii

  condition:
    uint16(0) == 0x7274 and
    8 of them
}