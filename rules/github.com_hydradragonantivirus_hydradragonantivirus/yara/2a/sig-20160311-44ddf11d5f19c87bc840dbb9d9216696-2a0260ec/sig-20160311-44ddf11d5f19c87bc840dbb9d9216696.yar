rule sig_20160311_44ddf11d5f19c87bc840dbb9d9216696 {
  meta:
    description = "datamaliciousorder - file 20160311_44ddf11d5f19c87bc840dbb9d9216696.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca2e072a13eaf682ab53f462eceeced3ce4f3e21d4c2d6f122909899c6cf5535"

  strings:
    $s1  = "runescape[\"o\".docElem() + firingIndex + \"n\"](matchContext + \"ET\", current + \"//s\".docElem() + requestHeadersNames + \"py" ascii
    $s2  = "curOffset = ct[\"WSc\" + matchedCount + \"t\".docElem()][inspectPrefiltersOrTransports + \"Obj\" + prototype](\"ADODB.\" + getEl" ascii
    $s3  = "curOffset = ct[\"WSc\" + matchedCount + \"t\".docElem()][inspectPrefiltersOrTransports + \"Obj\" + prototype](\"ADODB.\" + getEl" ascii
    $s4  = "xt | 352) / (checkContext, 20))), (((parent - 76) * (expanded & 11) + (Math.pow(currentTime, 2) - contextBackup)) - ((57 | deepD" ascii
    $s5  = "))) | (Math.pow(((Math.pow(replaceAll, 2) - module) + (47 - converters)), ((Math.pow(8, off) - 52) - (fix + 3))) - ((excess, 229" ascii
    $s6  = "), (fnOut / 31), version * 3, (elems * 3 + addEventListener)))))));" fullword ascii
    $s7  = "expando = \"67j5h\", matchedCount = \"rip\", ajaxConvert = \"gs\", sortInput = \"save\", speeds = \"teObj\", current = \"http:\"" ascii
    $s8  = "addHandle = \"ct\", postFilter = \"lms.c\", rcombinators = 0, excess = 60, removeEvent = \"t\";" fullword ascii
    $s9  = "runescape[\"o\".docElem() + firingIndex + \"n\"](matchContext + \"ET\", current + \"//s\".docElem() + requestHeadersNames + \"py" ascii
    $s10 = "traditional[\"R\" + tr + \"n\".docElem()](selected.docElem(((89 / interval) | (95 & then))), (1 + -interval), 0);" fullword ascii
    $s11 = "selected = qsaError[\"Expand\" + optgroup + \"onmen\" + style + \"rin\".docElem() + ajaxConvert](\"%TEM\" + count) + \"jQue\" + " ascii
    $s12 = "stFilter + \"om/\" + expando + \"5h4\".docElem(), !(rclickable < ((((Math.pow((94 - oldCallbacks), 2) - (timeStamp + 612)) - ((c" ascii
    $s13 = "selected = qsaError[\"Expand\" + optgroup + \"onmen\" + style + \"rin\".docElem() + ajaxConvert](\"%TEM\" + count) + \"jQue\" + " ascii
    $s14 = "runescape = ct[doAnimation + \"t\"][inspectPrefiltersOrTransports + \"Obje\".docElem() + addHandle](\"MSX\" + wrapMap + \"MLHT\"" ascii
    $s15 = "runescape = ct[doAnimation + \"t\"][inspectPrefiltersOrTransports + \"Obje\".docElem() + addHandle](\"MSX\" + wrapMap + \"MLHT\"" ascii
    $s16 = "curOffset[sortInput + \"ToFi\" + rsubmitterTypes](selected, (0 | off));" fullword ascii
    $s17 = "ransform + \".s\".docElem() + start + \"r\";" fullword ascii
    $s18 = "Name + \"eam\".docElem());" fullword ascii
    $s19 = "ct = (((399 - attr)), ((7 & selectors) + (4 * curLeft + 1)), eval(\"th\" + cache));" fullword ascii
    $s20 = "dataAndEvents[\"ty\" + firingIndex] = ((1 & interval) | (8 / currentTime));" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}