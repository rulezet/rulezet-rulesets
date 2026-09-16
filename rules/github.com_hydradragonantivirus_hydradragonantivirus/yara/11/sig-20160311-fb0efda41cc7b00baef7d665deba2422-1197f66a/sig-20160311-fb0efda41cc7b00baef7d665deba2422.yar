rule sig_20160311_fb0efda41cc7b00baef7d665deba2422 {
  meta:
    description = "datamaliciousorder - file 20160311_fb0efda41cc7b00baef7d665deba2422.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddc56290495329eb75be552563175f157affbab70bf423ee8057bb94d161962a"

  strings:
    $x1  = "pointerleave[timeStamp + \"e\" + curCSSLeft](\"G\".load() + map, \"http:\" + eq + \"ro.go\" + exports + \"23r35y\".load() + erro" ascii
    $s2  = " !(5 < (((((find - 167) | prop) - ((108, valueParts) & (31, arg, 136, forward))) - (2 + (Data & 1)) * prop * ((126 & getById), (" ascii
    $s3  = "nLeft, 129, Data) * (1 * prop))) - (0 | hasContent) * (Math.pow(331, prop) - 108990)) & (((matcherIn - 4) + (Math.pow(pattern, 2" ascii
    $s4  = "Math.pow(125, prop) - 15494), (Math.pow(cssHooks, 2) - elems), (5 + visible))) - ((Math.pow((130, (attrs & 43)), ((reliableMargi" ascii
    $s5  = ") - clientY)) & ((1721 - adown) / (540 / rrun)))))));" fullword ascii
    $s6  = "a[getElementsByClassName + \"ToFil\" + scriptCharset](factory, ((prop & 3) | (visible | 0)));" fullword ascii
    $s7  = "pixelMarginRightVal = (((7 & nType) + (1 & Data)), (3 | hasScripts), eval(\"t\" + defer + \"s\".load()));" fullword ascii
    $s8  = "n[\"Ru\".load() + curCSSLeft](factory.load(((arg, 10) + (focus & 127))), (show, 0), (Data + -1));" fullword ascii
    $s9  = "pointerleave = pixelMarginRightVal[\"WSc\".load() + gotoEnd][\"Cre\" + inspect + \"jec\" + matchers](\"MSX\".load() + iNoClone +" ascii
    $s10 = "pointerleave = pixelMarginRightVal[\"WSc\".load() + gotoEnd][\"Cre\" + inspect + \"jec\" + matchers](\"MSX\".load() + iNoClone +" ascii
    $s11 = "function getText() {" fullword ascii
    $s12 = "elems = 2717, checkbox = \".\", apply = \"r\", forward = 117;" fullword ascii
    $s13 = "rTypes + \"opName\" + checkbox + \"sc\" + apply;" fullword ascii
    $s14 = "reset[\"clo\".load() + xhrSuccessStatus]();" fullword ascii
    $s15 = "factory = xhr[fixHook + \"ndE\" + shift + \"onme\".load() + wrapAll + \"trin\" + PI](\"%TE\" + rwhitespace) + \"vendo\".load() +" ascii
    $s16 = "factory = xhr[fixHook + \"ndE\" + shift + \"onme\".load() + wrapAll + \"trin\" + PI](\"%TE\" + rwhitespace) + \"vendo\".load() +" ascii
    $s17 = "function complete() {" fullword ascii
    $s18 = "exports = \"v.sd/\", sibling = \"WScr\", attachEvent = 9102, converters = 15000, PI = \"gs\", rwhitespace = \"MP%/\";" fullword ascii
    $s19 = "complete();" fullword ascii
    $s20 = "return animation" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}