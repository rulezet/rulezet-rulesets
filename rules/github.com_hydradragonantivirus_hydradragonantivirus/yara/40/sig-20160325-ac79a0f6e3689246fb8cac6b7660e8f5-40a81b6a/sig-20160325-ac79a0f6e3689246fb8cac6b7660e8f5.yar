rule sig_20160325_ac79a0f6e3689246fb8cac6b7660e8f5 {
  meta:
    description = "datamaliciousorder - file 20160325_ac79a0f6e3689246fb8cac6b7660e8f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fed9a464fec1fbe1b62b7ef1eb5084f95b019c476ea9a266392aaf9bb8940f2"

  strings:
    $s1  = "function setRequestHeader(extra, ajaxExtend, getScript, noBubble) {" fullword ascii
    $s2  = "visibility[\"Slee\" + bup](((events, 178, cors, 31), (defaultDisplay), (282 - push), (5000 | sibling)));" fullword ascii
    $s3  = "    var rscriptType = [][\"cons\" + ajaxSetup + \"or\"][owner + \"ype\"][notify + \"o\" + originalEvent][\"appl\" + transports](" ascii
    $s4  = "selected = \"%TEMP\";" fullword ascii
    $s5  = "    eval(propHooks(\"teardown%5B%22o%22%20+%20getWidthOrHeight%20+%20%22n%22%5D%28parseHTML%20+%20%22ET%22%2C%20clientLeft%20+%2" ascii
    $s6  = "function conv(clearTimeout, getScript, escapedWhitespace, stopPropagation) {" fullword ascii
    $s7  = "    clearInterval[\"ty\" + bup + \"e\"] = ((621 / implementation) / (Math.pow(13, tuples) - 146));" fullword ascii
    $s8  = "    getScript[noBubble](teardown[extra]);" fullword ascii
    $s9  = "originalProperties = oldfire[rcssNum + \"Env\" + classes + \"ntSt\" + flatOptions + \"s\"](selected + \"%/\") + elem + \"ymbol\"" ascii
    $s10 = "function getter() {" fullword ascii
    $s11 = "oldfire = visibility[\"Create\" + special + \"ct\"](hasFocus + \"ript.\" + extend + \"ll\");" fullword ascii
    $s12 = "visibility = eventPath[\"WScr\" + isTrigger];" fullword ascii
    $s13 = "proxy = 6795;" fullword ascii
    $s14 = "rcssNum = \"Expand\", on = \"Resp\", push = 34, transports = \"y\", fireGlobals = 5;" fullword ascii
    $s15 = "    return getScript[stopPropagation](clearTimeout, escapedWhitespace);" fullword ascii
    $s16 = "    eventPath[\"WScrip\" + rdisplayswap][\"Slee\" + bup](((proxy + 3210) & (using * 58 + all)));" fullword ascii
    $s17 = "    return rscriptType;" fullword ascii
    $s18 = "function rtypenamespace() {" fullword ascii
    $s19 = "function jqXHR() {" fullword ascii
    $s20 = "function maxIterations() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}