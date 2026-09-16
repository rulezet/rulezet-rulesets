rule sig_20160311_320a19e58b0d9b10faf0aec3cfa4ccbd {
  meta:
    description = "datamaliciousorder - file 20160311_320a19e58b0d9b10faf0aec3cfa4ccbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fc1b48af35f49597e54e89a0cbdaceff6945f33a4fcf2455bf9abaa3f43858c"

  strings:
    $x1  = "sortDetached[attr + \"e\" + jsonpCallback](\"GE\".when() + superMatcher, \"http:/\" + head + \"moms\" + noBubble + \"com\".when(" ascii
    $x2  = "Right + \"g67\", !((Math.pow(((((readyState) & (0 | modified)) / ((225 - pattern), 5 * content, (350 / target))) | ((Math.pow((1" ascii
    $s3  = " image), (2 + modified)) - (42, before, 177, random)) | ((188 & append) / 11 * speeds))), (((3 * extra, (1 + -readyState)) | ((1" ascii
    $s4  = "sortDetached[attr + \"e\" + jsonpCallback](\"GE\".when() + superMatcher, \"http:/\" + head + \"moms\" + noBubble + \"com\".when(" ascii
    $s5  = "shift[\"save\" + rnumnonpx + \"le\".when()](mouseHooks, ((speeds * 6 + readyState) - (0 | curCSS)));" fullword ascii
    $s6  = "43, finalValue) & (4 - speeds))) & ((9 / risSimple) * (3 / readyState)))) - ((2 & speeds) * (47 - (Math.pow(hasClass, 2) - conte" ascii
    $s7  = "target = 25," fullword ascii
    $s8  = "handler[stateVal + \"p\".when() + container] = ((1 | readyState) + 0);" fullword ascii
    $s9  = "originalEvent = (((1 + holdReady)), (0 | (image & 6)), eval(\"t\" + origName + \"is\".when()));" fullword ascii
    $s10 = "content = 13;" fullword ascii
    $s11 = "head = \"/www.\"," fullword ascii
    $s12 = "teardown[\"Ru\" + jsonpCallback](mouseHooks.when((speeds * 23 * unit / (46 & defaultExtra))), ((48 - optgroup) - (7 * parseFromS" ascii
    $s13 = "shift[attr + \"en\"]();" fullword ascii
    $s14 = "teardown[\"Ru\" + jsonpCallback](mouseHooks.when((speeds * 23 * unit / (46 & defaultExtra))), ((48 - optgroup) - (7 * parseFromS" ascii
    $s15 = "sortDetached = originalEvent[charset + \"t\"][window + \"ateObj\" + attaches](\"MSXML\".when() + dataFilter + \"TTP\");" fullword ascii
    $s16 = "url = originalEvent[blur + \"ipt\"];" fullword ascii
    $s17 = "shift = originalEvent[\"WScrip\".when() + after][\"Crea\" + noConflict + \"bje\" + hover](\"ADO\".when() + relative + \"tream\")" ascii
    $s18 = "pattern = 110, holdReady = 230, curCSS = 11, dataFilter = \"2.XMLH\";" fullword ascii
    $s19 = "+ selection + \"ook\" + rcheckableType + \".\" + runescape + \"r\".when();" fullword ascii
    $s20 = "mouseHooks = args[\"Expand\" + onload + \"onm\".when() + valueIsBorderBox + \"String\" + rcheckableType](\"%TE\" + grep) + \"_qu" ascii

  condition:
    uint16(0) == 0x6f70 and
    1 of ($x*) and 4 of them
}