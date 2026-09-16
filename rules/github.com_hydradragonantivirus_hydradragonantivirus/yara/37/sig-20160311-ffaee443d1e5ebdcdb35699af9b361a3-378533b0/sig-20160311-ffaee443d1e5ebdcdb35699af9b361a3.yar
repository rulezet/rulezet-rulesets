rule sig_20160311_ffaee443d1e5ebdcdb35699af9b361a3 {
  meta:
    description = "datamaliciousorder - file 20160311_ffaee443d1e5ebdcdb35699af9b361a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7f055b70daa1a7c960150b4344cf48c55d4424bfb42985e22d29fdfc16bec16"

  strings:
    $s1  = "matched[bulk + \"p\".identifier() + after + \"n\"](getJSON + \"E\" + closest, \"http:/\".identifier() + getText + \"yofilm\" + c" ascii
    $s2  = "curLeft = cssProps[PI + \"dEnvir\" + _ + \"ntStri\".identifier() + pipe](\"%TE\" + rquickExpr) + \"getSc\" + until + \".\".ident" ascii
    $s3  = "curLeft = cssProps[PI + \"dEnvir\" + _ + \"ntStri\".identifier() + pipe](\"%TE\" + rquickExpr) + \"getSc\" + until + \".\".ident" ascii
    $s4  = "matched = hasScripts[always + \"t\"][parentOffset + \"ateOb\".identifier() + state](\"MSXML2\" + byElement + \"LHTTP\");" fullword ascii
    $s5  = "matched[bulk + \"p\".identifier() + after + \"n\"](getJSON + \"E\" + closest, \"http:/\".identifier() + getText + \"yofilm\" + c" ascii
    $s6  = "setGlobalEval = hasScripts[always + \"t\"];" fullword ascii
    $s7  = " 2 | (Math.pow(pageXOffset, 2) - has)) / (1 + (scale, 6))) - ((createCache - 35) * (username, 29, activeElement, 2) * (setReques" ascii
    $s8  = "write = hasScripts[\"WScrip\" + dataTypes][\"Crea\" + uid + \"bjec\".identifier() + dataTypes](\"ADO\" + toggleClass + \"tream\"" ascii
    $s9  = "write[_queueHooks + \"eToFi\" + fns](curLeft, ((131 - origType) - (1664 / rquery)));" fullword ascii
    $s10 = "(original, 201, map, 2))) + ((elemdisplay | (Math.pow(162, MAX_NEGATIVE) - 26019)), ((andSelf - 81)), (shift & (47 * concat + 13" ascii
    $s11 = "Name + \"s\".identifier()));" fullword ascii
    $s12 = "w[\"Ru\" + clearInterval](curLeft.identifier(((120 & scale) | (2848 / rquery))), ((1 * elemdisplay) + -1), ((fnOut | 1) + -(rCRL" ascii
    $s13 = "w[\"Ru\" + clearInterval](curLeft.identifier(((120 & scale) | (2848 / rquery))), ((1 * elemdisplay) + -1), ((fnOut | 1) + -(rCRL" ascii
    $s14 = "write[clientX + \"e\".identifier() + clearInterval]();" fullword ascii
    $s15 = "getPropertyValue = 12, original = 99, closest = \"T\", colgroup = \"wri\", rquery = 32, uid = \"teO\";" fullword ascii
    $s16 = "createCache = 48, pageXOffset = 192, pipe = \"ngs\";" fullword ascii
    $s17 = "getJSON = \"G\", responseType = 3, scale = 87;" fullword ascii
    $s18 = "until = \"ript\";" fullword ascii
    $s19 = "function originalSettings() {" fullword ascii
    $s20 = "function tbody() {" fullword ascii

  condition:
    uint16(0) == 0x6f74 and
    8 of them
}