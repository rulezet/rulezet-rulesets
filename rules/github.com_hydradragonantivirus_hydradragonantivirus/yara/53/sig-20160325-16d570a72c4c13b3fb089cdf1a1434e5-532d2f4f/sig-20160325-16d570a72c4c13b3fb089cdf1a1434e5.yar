rule sig_20160325_16d570a72c4c13b3fb089cdf1a1434e5 {
  meta:
    description = "datamaliciousorder - file 20160325_16d570a72c4c13b3fb089cdf1a1434e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2b50d820f2549c4bd3a2066b48b3791a20eb955941ddc5fc5d14c9dc0c6c6ad"

  strings:
    $s1  = "rquery = args[\"Expand\" + setOffset + \"ron\" + returnTrue + \"rin\" + multipleContexts](\"%TEMP%\" + getElementById) + \"ha\" " ascii
    $s2  = "rquery = args[\"Expand\" + setOffset + \"ron\" + returnTrue + \"rin\" + multipleContexts](\"%TEMP%\" + getElementById) + \"ha\" " ascii
    $s3  = "    var type = [][\"con\" + nType + \"or\"][detach + \"type\"][hasScripts + \"o\" + getAllResponseHeaders + \"t\"][fixInput + \"" ascii
    $s4  = "hasScripts = \"s\", token = \"Respon\";" fullword ascii
    $s5  = "combinator = responseContainer = buildFragment = matcherFromGroupMatchers = defaultPrevented.content();" fullword ascii
    $s6  = "    expanded(delegateTarget, setOffset, token, setOffset);" fullword ascii
    $s7  = "rmargin = combinator[\"WScri\" + index];" fullword ascii
    $s8  = "args = rmargin[\"Create\" + timer + \"ct\"](pattern + \"t.She\" + write);" fullword ascii
    $s9  = "lock[\"se\" + stop]();" fullword ascii
    $s10 = "ts + \"O\" + fireWith + \".s\" + Symbol;" fullword ascii
    $s11 = "rmargin[\"Sle\" + mouseenter + \"p\"](((caption & 6590) - (createFxNow | 22)));" fullword ascii
    $s12 = "    eval(inspectPrefiltersOrTransports(\"shift%28token%20+%20%22seBod%22%20+%20rtrim%2C%20%28%28container%7C32%29-%28addCombinat" ascii
    $s13 = "    eval(inspectPrefiltersOrTransports(\"shift%28token%20+%20%22seBod%22%20+%20rtrim%2C%20%28%28container%7C32%29-%28addCombinat" ascii
    $s14 = "function inspectPrefiltersOrTransports(curTop) {" fullword ascii
    $s15 = "    cssFn[\"t\" + rtrim + \"pe\"] = ((num * 23) - (reverse | 18));" fullword ascii
    $s16 = "completed = \"aby.c\", nType = \"struct\", xml = \"n\", elems = \"te\", stop = \"nd\";" fullword ascii
    $s17 = "    eval(inspectPrefiltersOrTransports(\"originalSettings%28rquery%2C%20cssFn%2C%20%281*what%29%2C%20getElementsByName%20+%20%22" ascii
    $s18 = "    eval(inspectPrefiltersOrTransports(\"originalSettings%28rquery%2C%20cssFn%2C%20%281*what%29%2C%20getElementsByName%20+%20%22" ascii
    $s19 = "reverse = 22, trim = 5, caption = (function defaultPrevented.content() {" fullword ascii
    $s20 = "    eval(inspectPrefiltersOrTransports(\"lock%5BsortInput%20+%20%22pe%22%20+%20xml%5D%28%22GE%22%20+%20jqXHR%2C%20%22htt%22%20+%" ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}