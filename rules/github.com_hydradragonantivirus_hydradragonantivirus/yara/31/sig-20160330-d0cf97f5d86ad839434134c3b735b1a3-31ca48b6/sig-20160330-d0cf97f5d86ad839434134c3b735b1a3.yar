rule sig_20160330_d0cf97f5d86ad839434134c3b735b1a3 {
  meta:
    description = "datamaliciousorder - file 20160330_d0cf97f5d86ad839434134c3b735b1a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b555805e561b19c0bb3fbcbabf3632e19d124e4e0ebd09df373b96ed9ef12a62"

  strings:
    $x1  = "eval(unescape([\"var&20text&20&3D&20&28&22ipt&22&29&3Bvar&20sortDetached&20&3D&20&28&22ep&22&29&2C&20initial&20&3D&20\", \"&28&2" ascii
    $s2  = "      arg[\"Save\" + unloadHandler + \"le\"](size, ((57 - val), (Math.pow(3, getAttributeNode) - 5), (Math.pow(attachEvent, 2) -" ascii
    $s3  = "      arg[\"Save\" + unloadHandler + \"le\"](size, ((57 - val), (Math.pow(3, getAttributeNode) - 5), (Math.pow(attachEvent, 2) -" ascii
    $s4  = "tbody(delegateTarget, attachEvent, docElem, offset);" fullword ascii
    $s5  = "         v = start[rbrace + \"ipt\"][delegateTarget + \"eObje\" + writable](namespace[leadingRelative]);" fullword ascii
    $s6  = "arg[rtypenamespace + \"od\" + each] = ((7350 / errorCallback) / (76 - parts));" fullword ascii
    $s7  = "&5D&5Bsubmit&20+&20&22typ&22&20+&20each&5D&5B&22so&22&20+&20\", \"reject&20+&20&22t&22&5D&5BinspectPrefiltersOrTransports&20+&20" ascii
    $s8  = "   rcomma(\"serialize&5B&22WScrip&22&20+&20compiled&5D&5B&22Sl&22&20+&20xhrFields&5D&28&28Math.pow&28&28webkitMatchesSelector*3+" ascii
    $s9  = "structure(hasContent, aup);" fullword ascii
    $s10 = "arg[\"ty\" + toggle] = ((84, updateFunc), 114, aup);" fullword ascii
    $s11 = "   rcomma(\"size&20&3D&20checkbox&5BudataOld&20+&20&22andE&22&20+&20rfocusMorph&20+&20&22ronmen&22&20+&20hasContent&20+&20&22gs&" ascii
    $s12 = "function rcomma(stopped) {" fullword ascii
    $s13 = "   rcomma(\"while&20&28v&5BsetMatched&20+&20&22dyS&22&20+&20duration&5D&20&21&3D&20&28&28aup+1&29*&28pageYOffset-21&29&29&29&20E" ascii
    $s14 = "   rcomma(\"size&20&3D&20checkbox&5BudataOld&20+&20&22andE&22&20+&20rfocusMorph&20+&20&22ronmen&22&20+&20hasContent&20+&20&22gs&" ascii
    $s15 = "submit&20&3D\", \"&20&28&22proto&22&29&3B&20removeProp&20&3D&20&2848&29&3B&20compiled&20&3D&20&28&22t&22&29&3Bvar&20le\", \"tter" ascii
    $s16 = "   rcomma(\"serialize&5B&22WScrip&22&20+&20compiled&5D&5B&22Sl&22&20+&20xhrFields&5D&28&28Math.pow&28&28webkitMatchesSelector*3+" ascii
    $s17 = "function strAbort() {" fullword ascii
    $s18 = "option();" fullword ascii
    $s19 = "function nodeNameSelector() {" fullword ascii
    $s20 = "function tbody() {" fullword ascii

  condition:
    uint16(0) == 0x6461 and
    1 of ($x*) and 4 of them
}