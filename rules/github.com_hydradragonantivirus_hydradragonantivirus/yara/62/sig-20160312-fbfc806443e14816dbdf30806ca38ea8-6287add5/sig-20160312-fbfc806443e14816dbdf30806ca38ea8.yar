rule sig_20160312_fbfc806443e14816dbdf30806ca38ea8 {
  meta:
    description = "datamaliciousorder - file 20160312_fbfc806443e14816dbdf30806ca38ea8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f7817a0de128ca429911cb6c80bd2538ec14fd70f453ec2bf9e151bbc4c5d07"

  strings:
    $s1  = "cssFn[reliableMarginLeft + \"en\"](noop + \"T\", rescape + \"//n\".content() + jQuery + \"lita\" + has + \"0954t\" + type, !((((" ascii
    $s2  = " + 6))), ((Math.pow((responseHeadersString + 4), doScroll) - (1244 - getElementsByName)) - ((776 | elemdisplay) / (78 - last))))" ascii
    $s3  = "queue = getPropertyValue[adown + \"teO\" + add](\"WScri\".content() + pointerleave + \"ell\");" fullword ascii
    $s4  = " offsetParent)))) & ((((36 - offsetParent) + (6 + byElement)) - (Math.pow((5 * newUnmatched + 2), (complete / 21)) - (Math.pow(e" ascii
    $s5  = "finalValue[\"Ru\" + Deferred](high.content(((4250 / stateString) & (110 - round))), ((47, disconnectedMatch, 180, fire) - (15 * " ascii
    $s6  = "height[pattern + \"File\".content()](high, (36 - stateString));" fullword ascii
    $s7  = "finalValue[\"Ru\" + Deferred](high.content(((4250 / stateString) & (110 - round))), ((47, disconnectedMatch, 180, fire) - (15 * " ascii
    $s8  = "high = queue[timeout + \"dEnvir\" + tag + \"tStrin\".content() + postSelector](\"%TE\" + code) + \"_rem\" + createCache + \"ta\"" ascii
    $s9  = "high = queue[timeout + \"dEnvir\" + tag + \"tStrin\".content() + postSelector](\"%TE\" + code) + \"_rem\" + createCache + \"ta\"" ascii
    $s10 = "height[\"o\" + colgroup + \"e\".content() + Deferred]();" fullword ascii
    $s11 = " * 5) - doScroll * 2) + (subtract * (1 * doScroll))) | (((2 * callbackInverse) - (324 / postDispatch)) * ((1 | subtract) + (14 /" ascii
    $s12 = "detectDuplicates = (((66 | insertBefore) + (31 * doScroll + 29)), ((hide, 218, visible, 70) - (off - 37)), eval(\"t\" + list + " ascii
    $s13 = "height = detectDuplicates[\"WSc\" + oldCache + \"t\"][conv + \"Object\".content()](domManip + \"B.Str\" + width);" fullword ascii
    $s14 = "Scroll + 10)), ((insertBefore - 24)));" fullword ascii
    $s15 = "isBorderBox = (function String.prototype.content() {" fullword ascii
    $s16 = "cssFn = detectDuplicates[deep + \"t\".content()][siblingCheck + \"ateO\" + add](\"MSXML2\" + pop + \"TP\".content());" fullword ascii
    $s17 = "cssFn[reliableMarginLeft + \"en\"](noop + \"T\", rescape + \"//n\".content() + jQuery + \"lita\" + has + \"0954t\" + type, !((((" ascii
    $s18 = "detectDuplicates = (((66 | insertBefore) + (31 * doScroll + 29)), ((hide, 218, visible, 70) - (off - 37)), eval(\"t\" + list + " ascii
    $s19 = " + method + \"s\" + submit + \"r\";" fullword ascii
    $s20 = "complete = 42;" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}