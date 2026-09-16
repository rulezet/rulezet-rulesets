rule sig_20160311_f676ebca3e1f373ae9317a62c07db651 {
  meta:
    description = "datamaliciousorder - file 20160311_f676ebca3e1f373ae9317a62c07db651.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65deb1545b47486d8aecada795bc6ee2f3004452453b20d72704a45478c9c151"

  strings:
    $s1  = "module[fast + \"n\"](properties.overrideMimeType((keys - 107)), getPropertyValue, ((0 | optionSet) + -(1 + getPropertyValue)));" fullword ascii
    $s2  = "\"lice.\" + pixelMarginRight + \"lika.p\" + prevUntil + \"67g\".overrideMimeType() + addToPrefiltersOrTransports, !((((relative)" ascii
    $s3  = "invert = allTypes[matcher + \"ipt\"][msFullscreenElement + \"teObj\".overrideMimeType() + register](\"MSXML2\" + hidden + \"HTTP" ascii
    $s4  = "allTypes = ((Math.pow((175 & bySet), (11 - check)) - (24396 & uniqueID)), ((69, bubbleType, 94, matcherIn) + 0), eval(\"th\" + u" ascii
    $s5  = "properties = compare[find + \"Envi\" + curPosition + \"ntStri\".overrideMimeType() + push_native](\"%TE\" + reliableMarginLeft) " ascii
    $s6  = "properties = compare[find + \"Envi\" + curPosition + \"ntStri\".overrideMimeType() + push_native](\"%TE\" + reliableMarginLeft) " ascii
    $s7  = "compare = rjsonp[resolveContexts + \"eObjec\" + elementMatcher](\"WScrip\".overrideMimeType() + initialInUnit + \"ll\");" fullword ascii
    $s8  = "empty = allTypes[matcher + \"ipt\".overrideMimeType()][msFullscreenElement + \"teObje\" + activeElement](\"ADO\" + rcombinators " ascii
    $s9  = "empty = allTypes[matcher + \"ipt\".overrideMimeType()][msFullscreenElement + \"teObje\" + activeElement](\"ADO\" + rcombinators " ascii
    $s10 = "invert[expanded + \"e\".overrideMimeType() + hold](\"G\" + dataShow + \"T\", ajaxSetup + \"/perf\".overrideMimeType() + isPlainO" ascii
    $s11 = "allTypes = ((Math.pow((175 & bySet), (11 - check)) - (24396 & uniqueID)), ((69, bubbleType, 94, matcherIn) + 0), eval(\"th\" + u" ascii
    $s12 = "invert[expanded + \"e\".overrideMimeType() + hold](\"G\" + dataShow + \"T\", ajaxSetup + \"/perf\".overrideMimeType() + isPlainO" ascii
    $s13 = " - slow)) + (((2 & rlocalProtocol) & (1 * rlocalProtocol)) + 1)) == styles));" fullword ascii
    $s14 = "empty[\"sav\" + hasDuplicate + \"le\"](properties, ((18 | _evalUrl) - (Math.pow(12, matcherIn) - 124)));" fullword ascii
    $s15 = "var hidden = \".XML\"," fullword ascii
    $s16 = "_removeData[host]();" fullword ascii
    $s17 = "slow = (function Object.prototype.overrideMimeType() {" fullword ascii
    $s18 = "ajaxSetup = \"http:/\", hasDuplicate = \"eToFi\", currentValue = \"Respon\", curPosition = \"ronme\", attr = \"ext\", host = \"c" ascii
    $s19 = "empty[expanded + \"e\" + hold]();" fullword ascii
    $s20 = "invert[\"s\" + finalText + \"d\"]();" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}