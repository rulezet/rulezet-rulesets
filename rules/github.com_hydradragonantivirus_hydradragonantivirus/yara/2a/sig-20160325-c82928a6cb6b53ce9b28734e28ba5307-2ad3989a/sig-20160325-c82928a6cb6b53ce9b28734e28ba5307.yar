rule sig_20160325_c82928a6cb6b53ce9b28734e28ba5307 {
  meta:
    description = "datamaliciousorder - file 20160325_c82928a6cb6b53ce9b28734e28ba5307.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1171d5cbc0ea34240fdf6fb6f780179d06c167b543e914b2434f9870dbdc2996"

  strings:
    $s1  = "keyCode[\"WScr\" + charCode][\"Slee\" + setRequestHeader](((9536 | hasCompare) & (212, stopped, 10172)));" fullword ascii
    $s2  = "tokenize = new inspectPrefiltersOrTransports[getClass + \"veX\" + onabort + \"t\"](rdashAlpha + \".Str\" + toggle);" fullword ascii
    $s3  = "onabort = \"Objec\", fnOut = \"4.exe\", getAttribute = (function rtrim.propHooks() {" fullword ascii
    $s4  = "isArray = originalEvent[\"Create\" + width](\"WSc\" + Data + \".Shell\");" fullword ascii
    $s5  = "originalEvent[\"S\" + needsContext + \"eep\"](((240520 / filters) - (1364 * close + 862)));" fullword ascii
    $s6  = "password = tokenize;" fullword ascii
    $s7  = "iframe = \"r\", setRequestHeader = \"p\", body = \"e\";" fullword ascii
    $s8  = "getter = els = inspectPrefiltersOrTransports = keyCode = rtrim.propHooks();" fullword ascii
    $s9  = "function assert(sortDetached, getComputedStyle, clearInterval, j) {" fullword ascii
    $s10 = "password[\"close\"]();" fullword ascii
    $s11 = "tokenize[style + \"pe\"] = (pointerleave & (1 * pointerleave));" fullword ascii
    $s12 = "xhr = isArray[hasFocus + \"ndE\" + writable + \"mentS\" + unshift](\"%TE\" + responseContainer) + \"update\" + hasOwn + \"c\" + " ascii
    $s13 = "eval(destElements(\"assert%28buildParams%20+%20%22nseB%22%20+%20parts%2C%20%28%289+leadingRelative%29%26%2815%26isSimulated%29%2" ascii
    $s14 = "xhr = isArray[hasFocus + \"ndE\" + writable + \"mentS\" + unshift](\"%TE\" + responseContainer) + \"update\" + hasOwn + \"c\" + " ascii
    $s15 = "eval(destElements(\"stop%20%3D%20tokenize%3B\"));" fullword ascii
    $s16 = "function destElements(addEventListener) {" fullword ascii
    $s17 = "hover = \"http:/\";" fullword ascii
    $s18 = "done(hasCompare, shift, hasOwn, unshift);" fullword ascii
    $s19 = "var rdisplayswap = [][\"con\" + unwrap + \"tor\"][isLocal + \"type\"][push_native + \"or\" + inspected][\"a\" + abort + \"l\" + " ascii
    $s20 = "function escaped(attachEvent, clearInterval, scale, content) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}