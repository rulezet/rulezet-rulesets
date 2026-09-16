rule sig_20160307_8f0c03459b70edccd5fbaa081b4b2ed8 {
  meta:
    description = "datamaliciousorder - file 20160307_8f0c03459b70edccd5fbaa081b4b2ed8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6593ad789b4094d247ca9f437e2b81f0adacfbfb301fdbbec1b4b9f42cf8f9b2"

  strings:
    $x1  = "props[andSelf + once + letter](removeProp + eventDoc, image + manipulationTarget + global + rtagName + currentTime + test + step" ascii
    $s2  = "t ^ 12) / (createDocumentFragment ^ 43))) * (((bind ^ 84) & (inspected / 37)) / ((Math.pow(bind, 2) - t) ^ (Math.pow(10, rnamesp" ascii
    $s3  = "props[andSelf + once + letter](removeProp + eventDoc, image + manipulationTarget + global + rtagName + currentTime + test + step" ascii
    $s4  = "t) - (15 & removeAttribute)) | (((1 * module) ^ (1 * jsonProp)) * 2))) - ((((rsingleTag / 22) * (module * 0)) | ((contentDocumen" ascii
    $s5  = "unqueued[mapped + getAll] = ((32 | fire) - (107 - namespace));" fullword ascii
    $s6  = "sibling = (((Math.pow(26, rnamespace) - 636) ^ (fromCharCode)), (((Math.pow(5, rnamespace) - 18) ^ (Math.pow(active, 2) - remove" ascii
    $s7  = "ace) - 83))) + ((t * 2 * rnamespace * (1 + module)) - ((Math.pow(193, rnamespace) - 36961) / (jsonProp | 8))))) == td));" fullword ascii
    $s8  = "handlers = matchesSelector[all + remaining](boolHook + isArrayLike + getStyles + stop + nodeValue);" fullword ascii
    $s9  = "timerId[checked + isImmediatePropagationStopped] = ((1 * module) + -(1 / module));" fullword ascii
    $s10 = "className = sibling[isXML + relative][all + risSimple + getWidthOrHeight + elemdisplay](which + max + unbind + setMatcher);" fullword ascii
    $s11 = "sibling[isXML + relative][click + stopImmediatePropagation](((230 - fixHook)));" fullword ascii
    $s12 = "props = sibling[handlerQueue + selectedIndex][all + dataUser + defineProperty](assert + suffix + jsonp + insertAfter + hasDuplic" ascii
    $s13 = "sibling[returnTrue + rbuggyMatches][box](((59 * bind + 36) * (clientY, 213, dataShow, 70) + (finalDataType, 66, leadingRelative)" ascii
    $s14 = "sibling[returnTrue + rbuggyMatches][box](((59 * bind + 36) * (clientY, 213, dataShow, 70) + (finalDataType, 66, leadingRelative)" ascii
    $s15 = "sibling = (((Math.pow(26, rnamespace) - 636) ^ (fromCharCode)), (((Math.pow(5, rnamespace) - 18) ^ (Math.pow(active, 2) - remove" ascii
    $s16 = "script = 30;" fullword ascii
    $s17 = "while (props[children + elemdisplay + diff + once] < ((2 | jsonProp) ^ (138 / responses))) {" fullword ascii
    $s18 = "props[returnFalse + clientLeft]();" fullword ascii
    $s19 = "matchesSelector = sibling[isXML + relative];" fullword ascii
    $s20 = "off[location](msg.nonce(), ((jsonProp / 12) ^ (jsonProp | 0)), ((module + -1)));" fullword ascii

  condition:
    uint16(0) == 0x7562 and
    1 of ($x*) and 4 of them
}