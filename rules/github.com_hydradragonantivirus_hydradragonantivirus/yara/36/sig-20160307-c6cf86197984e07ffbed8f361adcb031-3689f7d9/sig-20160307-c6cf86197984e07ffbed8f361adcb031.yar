rule sig_20160307_c6cf86197984e07ffbed8f361adcb031 {
  meta:
    description = "datamaliciousorder - file 20160307_c6cf86197984e07ffbed8f361adcb031.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca67a9f5967d91324140b1c65fc21025e1190c8687c05436572a471abff43a39"

  strings:
    $s1  = "  nextSibling[resolveWith + load][host](((isWindow ^ 15) - (Math.pow(what, 2) - winnow)));" fullword ascii
    $s2  = "mouseenter = nextSibling[location + tokenCache][cssText + end + getElementsByTagName](nodeName + lastModified + originalProperti" ascii
    $s3  = "nextSibling = (((864 / readyWait), (121 & defineProperty)), (((0 | valueParts) ^ (60 - tmp)), this));" fullword ascii
    $s4  = "dataUser = nextSibling[div1 + compiled + fired][type + globalEval + camelKey + box](ajax + amd + temp + tag);" fullword ascii
    $s5  = "nextSibling[location + Sizzle + on][host]((5 | valueParts) * (1 * file) * (5 | valueParts) * (4 + all) * (0 | file) * (1 + file)" ascii
    $s6  = " * (54 - bp) * (2 + compare));" fullword ascii
    $s7  = "+ run, !(8 == ((((all - (26 - blur)) * ((1 | all) ^ (3 & file))) + ((2 * file + 1) ^ (fnOver, 111, special))) | (((0 & special) " ascii
    $s8  = "mouseenter[rsubmitterTypes](replaceWith + rnoInnerhtml, dir + base + adown + tweeners + statusText + matchContext + parse + arg " ascii
    $s9  = "getClass = vendorPropName[unit + firing + contents + wait + global + pixelMarginRight](dataType + name) + sort + documentElement" ascii
    $s10 = "getClass = vendorPropName[unit + firing + contents + wait + global + pixelMarginRight](dataType + name) + sort + documentElement" ascii
    $s11 = "temp = \"DB.Str\";" fullword ascii
    $s12 = "  eased[marginDiv](getClass.source(), ((1 | special) & (0 / returned)), ((0 / simple) ^ (1 + -all)));" fullword ascii
    $s13 = "  dataUser[els + _jQuery + beforeunload + curTop](getClass, (2 + special));" fullword ascii
    $s14 = "mouseenter = nextSibling[location + tokenCache][cssText + end + getElementsByTagName](nodeName + lastModified + originalProperti" ascii
    $s15 = "vendorPropName = focus[funcName + write + preferredDoc + finish](selector + leadingRelative + inspectPrefiltersOrTransports + fi" ascii
    $s16 = "reverse = \".scr\";" fullword ascii
    $s17 = "vendorPropName = focus[funcName + write + preferredDoc + finish](selector + leadingRelative + inspectPrefiltersOrTransports + fi" ascii
    $s18 = "contents = \"viro\";" fullword ascii
    $s19 = "nextSibling[location + Sizzle + on][host]((5 | valueParts) * (1 * file) * (5 | valueParts) * (4 + all) * (0 | file) * (1 + file)" ascii
    $s20 = " + reverse;" fullword ascii

  condition:
    uint16(0) == 0x7369 and
    8 of them
}