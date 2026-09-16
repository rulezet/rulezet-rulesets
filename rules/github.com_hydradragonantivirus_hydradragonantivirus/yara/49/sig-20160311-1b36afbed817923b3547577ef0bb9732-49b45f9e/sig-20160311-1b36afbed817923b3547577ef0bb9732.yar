rule sig_20160311_1b36afbed817923b3547577ef0bb9732 {
  meta:
    description = "datamaliciousorder - file 20160311_1b36afbed817923b3547577ef0bb9732.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d35a4cf052cbab234113ac370bfb7cfbfb47d72eb5fded8c23c12afb56061626"

  strings:
    $s1  = "responseHeaders[success + \"p\".parseXML() + ofType + \"n\"](tbody + \"ET\", hidden + \"//50.2\".parseXML() + getScript + \"11.1" ascii
    $s2  = "responseHeaders[success + \"p\".parseXML() + ofType + \"n\"](tbody + \"ET\", hidden + \"//50.2\".parseXML() + getScript + \"11.1" ascii
    $s3  = "- pos) | (2 | initial))) + (((1 & fire) * (18 / rpseudo)) * ((23 - getJSON) & (1 + initial)))) + ((Math.pow((0 | (self * 6 + fir" ascii
    $s4  = "holdReady = gotoEnd[\"WScri\".parseXML() + fast][\"Cre\" + thead + \"ect\"](firstDataType + \"DB.\".parseXML() + keyHooks);" fullword ascii
    $s5  = "computed = \"%TEM\", insertBefore = \"u5y4\", image = \"t.Shel\", getScript = \"8.2\";" fullword ascii
    $s6  = "camelCase[\"Ru\".parseXML() + box](transport.parseXML(((close * 2 + isEmptyObject) | 3 * inArray)), ((1 & fire) * (50 - destElem" ascii
    $s7  = "e)), (218, (selector, 175, self))) - 11 * self * 7) / (Math.pow(((fire | 13) & (preFilter * 2 + inArray)), (0 | self)) - ((168 |" ascii
    $s8  = "transport = sel[augmentWidthOrHeight + \"andE\" + combinator + \"men\".parseXML() + activeElement + \"rings\"](computed + \"P%/" ascii
    $s9  = "function delegateTarget() {" fullword ascii
    $s10 = "transport = sel[augmentWidthOrHeight + \"andE\" + combinator + \"men\".parseXML() + activeElement + \"rings\"](computed + \"P%/" ascii
    $s11 = "holdReady[newCache + \"ToFi\" + what](transport, ((26 | self) - 2 * inArray * 2 * self));" fullword ascii
    $s12 = "hidden = \"http:\"," fullword ascii
    $s13 = "thead = \"ateObj\", initial = 0, nonce = 73, tabIndex = \"WScri\", rejectWith = \"ep\", border = 152;" fullword ascii
    $s14 = "gotoEnd = ((2 * toggle * 11 + (fire | 32)), ((Math.pow(fadeOut, 2) - oldCallbacks), (33 / toggle)), eval(\"t\" + add + \"is\".pa" ascii
    $s15 = "gotoEnd = ((2 * toggle * 11 + (fire | 32)), ((Math.pow(fadeOut, 2) - oldCallbacks), (33 / toggle)), eval(\"t\" + add + \"is\".pa" ascii
    $s16 = "camelCase[\"Ru\".parseXML() + box](transport.parseXML(((close * 2 + isEmptyObject) | 3 * inArray)), ((1 & fire) * (50 - destElem" ascii
    $s17 = "rflow, 28, ifModified), 19 * self * 2 * self), ((157680 / idx) / (752 / class2type)), ((13 & isEmptyObject) - (95, self)), ((24 " ascii
    $s18 = "string = gotoEnd[el + \"t\"];" fullword ascii
    $s19 = "height[linear + \"p\".parseXML() + ofType] = ((clazz / 14) * (fire * 1));" fullword ascii
    $s20 = "piled + \"in\".parseXML() + type + \"cr\";" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}