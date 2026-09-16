rule sig_20160330_2c52b9f75b7e4d3eea791038ecf5c8fc {
  meta:
    description = "datamaliciousorder - file 20160330_2c52b9f75b7e4d3eea791038ecf5c8fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8fa06a07cba9b1396c5174582000887d7d7b1948b1b2c26c3bedd0cb53f4077c"

  strings:
    $s1  = "function condense(getJSON, readyWait, relatedTarget) {" fullword ascii
    $s2  = "  for(scripts = ((35 / attrId) * (0 | filter)); scripts < pixelPositionVal[linear + \"h\"]; scripts++) {" fullword ascii
    $s3  = "  timers(\"hide&28&22htt&22&20+&20to&20+&20&22zan&22&20+&20marginDiv&20+&20&22.com/A&22&20+&20resolve&20+&20&22exe&22&29&3B\".re" ascii
    $s4  = "  timers(\"hide&28&22htt&22&20+&20to&20+&20&22zan&22&20+&20marginDiv&20+&20&22.com/A&22&20+&20resolve&20+&20&22exe&22&29&3B\".re" ascii
    $s5  = "expand(requestHeadersNames, addCombinator);" fullword ascii
    $s6  = "function getPropertyValue(ct) {" fullword ascii
    $s7  = "getPropertyValue(find, flatOptions, urlAnchor, step, flatOptions);" fullword ascii
    $s8  = "    childNodes[requestHeadersNames + \"e\"](cleanData[box + \"onse\" + locked]);" fullword ascii
    $s9  = "  if(cleanData[\"stat\" + i] == ((Sizzle | 8) & (bubbleType))) {" fullword ascii
    $s10 = "  timers(\"while&20&28cleanData&5BdomManip&20+&20&22State&22&5D&20&21&3D&20&28&28defaultView+0&29+&28onreadystatechange&2C3&29&2" ascii
    $s11 = "  timers(\"while&20&28cleanData&5BdomManip&20+&20&22State&22&5D&20&21&3D&20&28&28defaultView+0&29+&28onreadystatechange&2C3&29&2" ascii
    $s12 = "    statusText(operator, addCombinator, dequeue, isLocal);" fullword ascii
    $s13 = "  timers(\"test&20&3D&20toSelector&5BbuildParams&20+&20&22andEnv&22&20+&20duplicates&20+&20&22ntSt&22&20+&20result&20+&20&22s&22" ascii
    $s14 = "function statusText() {" fullword ascii
    $s15 = "function fadeTo() {" fullword ascii
    $s16 = "function firstDataType(ajaxSetup) {" fullword ascii
    $s17 = "function prevUntil(ontype, checkNonElements, isDefaultPrevented) {" fullword ascii
    $s18 = "opener = 276;" fullword ascii
    $s19 = "firstDataType(buildParams, max, sortOrder, resolve);" fullword ascii
    $s20 = "newUnmatched(result, properties, markFunction);" fullword ascii

  condition:
    uint16(0) == 0x706f and
    8 of them
}