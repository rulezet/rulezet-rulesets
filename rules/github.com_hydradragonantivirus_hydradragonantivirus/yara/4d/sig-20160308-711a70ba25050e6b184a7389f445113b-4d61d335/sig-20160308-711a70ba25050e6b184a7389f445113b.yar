rule sig_20160308_711a70ba25050e6b184a7389f445113b {
  meta:
    description = "datamaliciousorder - file 20160308_711a70ba25050e6b184a7389f445113b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba155225cbf206e0d072bb5d761203a5c8fa17077f01e178b870a25c470a0b14"

  strings:
    $s1  = "hasScripts[outermostContext + offsetWidth](serialize, match + promise + statusCode + tick + namespaces + hasData + rejectWith + " ascii
    $s2  = "exports, !(((((78 / getPropertyValue) + ((80 - before))) | (((188, bySet, 182, booleans) - (153 - sortOrder)) ^ ((1 * isArray) *" ascii
    $s3  = "cssShow = noGlobal[createHTMLDocument + prototype + apply + rcombinators + resolve + DOMParser](getWindow + guid) + rjsonp + poi" ascii
    $s4  = "hasScripts = fcamelCase[responseHeadersString + send][clone + crossDomain + closest](contentDocument + rcleanScript + result);" fullword ascii
    $s5  = "tmp[matchers + Symbol](hasScripts[stopImmediatePropagation + remaining + querySelectorAll + firing + origCount]);" fullword ascii
    $s6  = "cssShow = noGlobal[createHTMLDocument + prototype + apply + rcombinators + resolve + DOMParser](getWindow + guid) + rjsonp + poi" ascii
    $s7  = "namespaces = \"p.ua\", pixelPositionVal = 2184, col = \"a\", acceptData = \"R\", xhrSupported = \"eToF\", match = \"http:\";" fullword ascii
    $s8  = "nterleave + results + srcElements + actualDisplay + temp;" fullword ascii
    $s9  = "fcamelCase[getElementsByName + opener + rhash + identifier][newDefer + handle + rcssNum]((2 * boxSizingReliableVal * 827 * (remo" ascii
    $s10 = "^ ((one - 180) & (shift * 2 + r20))) / ((1 & isArray) * (25 - callback)) * ((108 / matcherIn) ^ (32 - pipe)) * ((1 + -isArray) |" ascii
    $s11 = "hasScripts[outermostContext + offsetWidth](serialize, match + promise + statusCode + tick + namespaces + hasData + rejectWith + " ascii
    $s12 = "while (hasScripts[fromCharCode + qsa] < ((2 * boxSizingReliableVal) + (0 ^ conv))) {" fullword ascii
    $s13 = "tmp = fcamelCase[orig + identifier][readyList + clientX + closest](wrapAll + rcombinators + originalEvent + col + cssNormalTrans" ascii
    $s14 = "tmp = fcamelCase[orig + identifier][readyList + clientX + closest](wrapAll + rcombinators + originalEvent + col + cssNormalTrans" ascii
    $s15 = "condense[w] = ((original / 2) - (toggle & 31));" fullword ascii
    $s16 = "fcamelCase[getElementsByName + opener + rhash + identifier][newDefer + handle + rcssNum]((2 * boxSizingReliableVal * 827 * (remo" ascii
    $s17 = "noGlobal = clientY[classNames + select + prev + type](getElementsByName + holdReady + srcElements + newDefer + which + newContex" ascii
    $s18 = "noGlobal = clientY[classNames + select + prev + type](getElementsByName + holdReady + srcElements + newDefer + which + newContex" ascii
    $s19 = "tmp[outermostContext + Symbol + after]();" fullword ascii
    $s20 = "fcamelCase = (((35, iframe, 35, removeProp) | (105 + url)), (((58 - hookFn), (1 + fired)), this));" fullword ascii

  condition:
    uint16(0) == 0x6f73 and
    8 of them
}