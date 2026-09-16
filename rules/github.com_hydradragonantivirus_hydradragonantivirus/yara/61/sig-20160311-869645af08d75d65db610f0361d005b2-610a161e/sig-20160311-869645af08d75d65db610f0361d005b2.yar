rule sig_20160311_869645af08d75d65db610f0361d005b2 {
  meta:
    description = "datamaliciousorder - file 20160311_869645af08d75d65db610f0361d005b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52d93ac30306e08a46d887ce1a385330ddcb61c659c7996fa2ce4a0dce300028"

  strings:
    $s1  = "tokenize[fixInput + \"pe\"] = ((copy * 1) & (postDispatch - 13));" fullword ascii
    $s2  = "removeAttribute = complete[\"Crea\" + queue + \"ct\"](rnative + \"ript\".tweeners() + emptyGet + \"ell\");" fullword ascii
    $s3  = "which[uniqueSort + \"u\" + rcomma](guid.tweeners(((215 - parent) & (101, speeds))), ((0 / checkContext) & 1), ((activeElement | " ascii
    $s4  = "which[uniqueSort + \"u\" + rcomma](guid.tweeners(((215 - parent) & (101, speeds))), ((0 / checkContext) & 1), ((activeElement | " ascii
    $s5  = "children[fix + \"pe\" + rcomma](\"G\" + find + \"T\".tweeners(), has + \"//perf\" + rparentsprev + \"alice\" + file + \"blik\".t" ascii
    $s6  = "scrollLeft + \"l/08h\" + refElements, !((Math.pow(((2 & (activeElement | 3)) * ((copy & 1) + fnOut) * 3 - (((compilerCache, 167," ascii
    $s7  = "fnOver = parents[forward + \"t\"][mouseHooks + \"eObje\" + propName](\"ADOD\".tweeners() + each + \"rea\" + handleObjIn);" fullword ascii
    $s8  = "oAnimation, 172) - (filters - 64)) / ((copy | 1) * (defaultValue / 24)))), (((types, 240, appendChild, 34) - (implementation + 1" ascii
    $s9  = "3)) + ((copy * 0) & (copy + -1)))) - ((((position & 3066) - (node - 164)) & ((innerHTML & 1011) + (expando & 733))) / ((copy & 1" ascii
    $s10 = "parents = (((3 | visibility) | (10, readyState, 168)), ((simple | 10) | activeElement), eval(\"th\" + defaultPrevented));" fullword ascii
    $s11 = "children = parents[bubbleType + \"ipt\".tweeners()][before + \"ateObj\" + isImmediatePropagationStopped](\"MSXML\" + ct + \"HTTP" ascii
    $s12 = "children[fix + \"pe\" + rcomma](\"G\" + find + \"T\".tweeners(), has + \"//perf\" + rparentsprev + \"alice\" + file + \"blik\".t" ascii
    $s13 = ") * (compareDocumentPosition / 2)) * ((copy * 2)) * (copy * (211, fnOut)))) > 6));" fullword ascii
    $s14 = "complete = parents[\"WScr\".tweeners() + second];" fullword ascii
    $s15 = "children = parents[bubbleType + \"ipt\".tweeners()][before + \"ateObj\" + isImmediatePropagationStopped](\"MSXML\" + ct + \"HTTP" ascii
    $s16 = "rejectWith = \"eToF\", last = \"e\", nativeStatusText = \"scro\", createHTMLDocument = 27, postDispatch = 14;" fullword ascii
    $s17 = "forward = \"WScrip\", expando = 910, p = 155, args = \"s\", each = \"B.St\", bubbleType = \"WScr\";" fullword ascii
    $s18 = "next[clone + \"lose\"]();" fullword ascii
    $s19 = "fnOver[\"sav\" + rejectWith + \"ile\".tweeners()](guid, ((58 & state) / 29));" fullword ascii
    $s20 = "guid = removeAttribute[tr + \"and\" + createButtonPseudo + \"nmen\".tweeners() + finish + \"ings\"](hidden + \"P%/\") + nativeSt" ascii

  condition:
    uint16(0) == 0x7564 and
    8 of them
}