rule sig_20160311_2ef840de712988a588ab4bad4a76dee5 {
  meta:
    description = "datamaliciousorder - file 20160311_2ef840de712988a588ab4bad4a76dee5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d87f232c9aaf4b839839076cba2c4e5506f9707e107a2247c46ec00fa1bdb3c"

  strings:
    $s1  = "(805 / addClass) - (Math.pow(31, iterator) - 928)) * ((byElement - 58) / (getAll & 11)) * pipe / ((Math.pow((27, noBubble, 394)," ascii
    $s2  = "pos[\"o\" + udataCur + \"n\".originalEvent()](checkDisplay + \"E\" + backgroundClip, \"htt\" + rescape + \"nobil\".originalEvent" ascii
    $s3  = "ajaxSettings = (((45 + oldCallbacks) & 51), ((Math.pow(getResponseHeader, 2) - rcomma) & (65 - firing)), eval(\"t\" + mouseleave" ascii
    $s4  = "ajaxSettings = (((45 + oldCallbacks) & 51), ((Math.pow(getResponseHeader, 2) - rcomma) & (65 - firing)), eval(\"t\" + mouseleave" ascii
    $s5  = " (iterator + 0)) - (dispatch + 56189)) / (fnOver * 7 * nodeType * 3 * pipe / (25 + soFar))))) > 3));" fullword ascii
    $s6  = "now = delay[leadingRelative + \"dEnv\".originalEvent() + nodeValue + \"nmen\" + responseHeaders + \"gs\"](tuple + \"MP%/\".origi" ascii
    $s7  = "fadeOut[fail + \"ToFi\" + n](now, ((always - 126), iterator));" fullword ascii
    $s8  = "now = delay[leadingRelative + \"dEnv\".originalEvent() + nodeValue + \"nmen\" + responseHeaders + \"gs\"](tuple + \"MP%/\".origi" ascii
    $s9  = "fail = \"save\", udataCur = \"pe\", responseHeaders = \"tStrin\", removeData = \"e\", owner = \"t\";" fullword ascii
    $s10 = "()) + winnow + \"erlea\" + notifyWith + \".\" + configurable + \"r\".originalEvent();" fullword ascii
    $s11 = "pipe = 3," fullword ascii
    $s12 = "p%22%5D%28%285*nodeType*3*pipe*2*nodeType*2*nodeType*5*iterator*3/%28hasCompare+31%29%29%29%3B%20%20%20%0D\"));" fullword ascii
    $s13 = "pos = ajaxSettings[curPosition + \"pt\"][DOMParser + \"eObjec\" + owner](\"MSXM\".originalEvent() + speed + \"XML\" + rcssNum);" fullword ascii
    $s14 = "optionSet[owner + \"y\" + udataCur] = (pseudo, 243, isXML, 1);" fullword ascii
    $s15 = "define = ajaxSettings[\"WScr\" + rprotocol];" fullword ascii
    $s16 = "eval(unescape(\"%20%20%20%20%20%20%20%20ajaxSettings%5BseekingTransport%20+%20%22ript%22.originalEvent%28%29%5D%5Bshift%20+%20%2" ascii
    $s17 = "iterator = 2, parts = 28, dispatch = 98606;" fullword ascii
    $s18 = "var newContext = this;" fullword ascii
    $s19 = "pseudo = 144;" fullword ascii
    $s20 = "function timeStamp() {" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}