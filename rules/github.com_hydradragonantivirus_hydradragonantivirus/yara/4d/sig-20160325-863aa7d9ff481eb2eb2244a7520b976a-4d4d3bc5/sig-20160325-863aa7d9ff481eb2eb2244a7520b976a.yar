rule sig_20160325_863aa7d9ff481eb2eb2244a7520b976a {
  meta:
    description = "datamaliciousorder - file 20160325_863aa7d9ff481eb2eb2244a7520b976a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdeeb0b370909f2dca28e3a87f162bd2a52a86685c276b3d51afd6505c3d9780"

  strings:
    $s1  = "elems = \"tion\", isSuccess = \"pro\", bindType = \"//t\", pos = \"%TEMP%\", finalValue = \"t.She\", handleObj = \"nd\";" fullword ascii
    $s2  = "fadeTo = push_native[view + \"Env\" + thead + \"entSt\" + specialEasing + \"s\"](pos + \"/\") + setRequestHeader + \"nt\" + firi" ascii
    $s3  = "current[\"Sleep\"](((7391 - fragment) + (420 | sel)));" fullword ascii
    $s4  = "function compile(ajaxTransport) {" fullword ascii
    $s5  = "push_native = current[\"Creat\" + nType + \"jec\" + rprotocol](\"WScrip\" + finalValue + \"ll\");" fullword ascii
    $s6  = "current = jsonProp[\"WScr\" + originalEvent];" fullword ascii
    $s7  = "function rcombinators() {" fullword ascii
    $s8  = "register(anim, XMLHttpRequest);" fullword ascii
    $s9  = "bind(unloadHandler, wrapMap, createTween, removeAttr, checkbox);" fullword ascii
    $s10 = "function bind() {" fullword ascii
    $s11 = "    propName[\"ty\" + ajaxSetup + \"e\"] = ((42 - image));" fullword ascii
    $s12 = "    eval(compile(\"box%5BcloneNode%20+%20%22pe%22%20+%20gotoEnd%5D%28%22GE%22%20+%20wrapMap%2C%20%22http%3A%22%20+%20bindType%20" ascii
    $s13 = "    eval(compile(\"box%5BcloneNode%20+%20%22pe%22%20+%20gotoEnd%5D%28%22GE%22%20+%20wrapMap%2C%20%22http%3A%22%20+%20bindType%20" ascii
    $s14 = "function win() {" fullword ascii
    $s15 = "function add() {" fullword ascii
    $s16 = "push = \"2.XM\";" fullword ascii
    $s17 = "function setAttribute() {" fullword ascii
    $s18 = "function rneedsContext() {" fullword ascii
    $s19 = "fragment = 2811;" fullword ascii
    $s20 = "}, 64), step = \"y\", image = 41;" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}