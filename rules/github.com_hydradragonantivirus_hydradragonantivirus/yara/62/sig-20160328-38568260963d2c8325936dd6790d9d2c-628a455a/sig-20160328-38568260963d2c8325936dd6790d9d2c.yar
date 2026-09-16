rule sig_20160328_38568260963d2c8325936dd6790d9d2c {
  meta:
    description = "datamaliciousorder - file 20160328_38568260963d2c8325936dd6790d9d2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "535b1fac38e850af8248159a475c44205feedb86d76a803c51422f4190d452f1"

  strings:
    $s1  = "isArray[\"WScri\" + firstDataType][\"Sleep\"]((Math.pow((55, relative, 118, progress), 2) - (ownerDocument * 4 + delegateTarget)" ascii
    $s2  = "isArray[list + \"t\"][pipe + \"p\"]((Math.pow((35, unloadHandler), 2) - (async, 68, msMatchesSelector, 7404284)));" fullword ascii
    $s3  = "selector(timerId(\"checkbox%20%3D%20%5Bfinish%20+%20%22ml2.%22%20+%20eventPath%20+%20%22rXM%22%20+%20Sizzle%20+%20%22P.6.0%22%2C" ascii
    $s4  = "while(merge[\"rea\" + tbody + \"e\"] != ((22 & finalDataType) - (3 * defaultPrevented + 2))) off[rwhitespace + \"pt\"][submit]((" ascii
    $s5  = "startTime[PI + \"oFi\" + self](rinputs, ((tokenize, 96, checkClone) - (6 & e)));" fullword ascii
    $s6  = "startTime[\"ty\" + tween + \"e\"] = ((postMap + 0) | postMap);" fullword ascii
    $s7  = "while(merge[\"rea\" + tbody + \"e\"] != ((22 & finalDataType) - (3 * defaultPrevented + 2))) off[rwhitespace + \"pt\"][submit]((" ascii
    $s8  = "selector(timerId(\"startTime%20%3D%20xhr%5Blist%20+%20%22t%22%5D%5BrCRLF%20+%20%22ateObj%22%20+%20overflowY%5D%28%22ADO%22%20+%2" ascii
    $s9  = "if(merge[\"sta\" + stopQueue] == (1 * (configurable))) {" fullword ascii
    $s10 = "merge = selectedIndex[list + \"t\"][updateFunc + \"teObje\" + isEmptyObject](checkbox[exports]);" fullword ascii
    $s11 = "selector(timerId(\"state%28attributes%20+%20%22%3A//ru%22%20+%20matchedCount%20+%20%22gmou%22%20+%20errorCallback%20+%20%22e.co%" ascii
    $s12 = "function qualifier(nodeName, contents) {" fullword ascii
    $s13 = "function ajaxHandleResponses(getAllResponseHeaders, statusCode, showHide) {" fullword ascii
    $s14 = "selector(timerId(\"rinputs%20%3D%20contextBackup%5B%22Exp%22%20+%20triggered%20+%20%22nvir%22%20+%20valueIsBorderBox%20+%20%22en" ascii
    $s15 = "merge[\"s\" + replaceAll + \"n\" + rfocusable]();" fullword ascii
    $s16 = "startTime[\"o\" + open + \"n\"]();" fullword ascii
    $s17 = "selector(timerId(\"contextBackup%20%3D%20isArray%5B%22WScrip%22%20+%20border%5D%5B%22Create%22%20+%20slideDown%20+%20%22ct%22%5D" ascii
    $s18 = "selector(timerId(\"startTime%5BsetFilters%20+%20%22e%22%5D%28merge%5Bunbind%20+%20%22pon%22%20+%20origFn%20+%20%22ody%22%5D%29%3" ascii
    $s19 = "contexts(msMatchesSelector, unbind, slideUp, ownerDocument, setFilters);" fullword ascii
    $s20 = "selector(timerId(\"startTime%5BsetFilters%20+%20%22e%22%5D%28merge%5Bunbind%20+%20%22pon%22%20+%20origFn%20+%20%22ody%22%5D%29%3" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}