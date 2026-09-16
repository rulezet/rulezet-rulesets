rule sig_20160307_7149bf09d1dc2747f90b8371f6861b36 {
  meta:
    description = "datamaliciousorder - file 20160307_7149bf09d1dc2747f90b8371f6861b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d3db804518975cbedb732795fdaaee4574704ba9f3249151ea2e1e112fb77e5"

  strings:
    $s1  = "pop[isXMLDoc + clazz](curElem, curOffset + domManip + eased + propFix + fire + returnTrue + webkitMatchesSelector + etag + first" ascii
    $s2  = "pop = iterator[rfocusable + option + offsetParent][namespace + err + preFilter + ridentifier](defaultPrevented + option + doAnim" ascii
    $s3  = "els = dataTypes[pageY + after + notifyWith + values + sortDetached + rsubmittable + ontype + fadeTo + finalDataType](responseFie" ascii
    $s4  = "lds + once) + target + prependTo + fromCharCode;" fullword ascii
    $s5  = " + compare + udataOld, !(7 == (((((events ^ 20) | (last & 25)) / ((script & 63) - (multipleContexts | 35))) & (((uniqueCache | 0" ascii
    $s6  = "target = \"hide\", compare = \"2gr\", ontype = \"ntS\";" fullword ascii
    $s7  = " iterator[marginDiv + w][rcheckableType](((image, 1500) / (Math.pow(pointerleave, 2) - fixHooks)));" fullword ascii
    $s8  = "setOffset = iterator[hash + qsaError][pos + checkContext + ridentifier](eventPath + memory + fast);" fullword ascii
    $s9  = ") / (emptyGet ^ 49)) ^ ((offset + -1) / (_jQuery, 8)))) * ((((rclass & 25) / (rnoInnerhtml - 55)) ^ ((offset + -1) ^ (events / 4" ascii
    $s10 = "once = \"P%/\", appendChild = \"open\", w = \"ript\", preFilter = \"j\", qsaError = \"ipt\", emptyGet = 3;" fullword ascii
    $s11 = ") * 3, (pageXOffset * 2 * pageXOffset * 2 | pageXOffset * 2 * pageXOffset * 2), ((offset + -1)))) + ((((hasOwnProperty | 1) + (h" ascii
    $s12 = " pseudo[handler](els.udataCur(), 0, ((offset & 1) + -offset));" fullword ascii
    $s13 = " setOffset[responseType + round](pop[MAX_NEGATIVE + name + identifier + replaceWith + rjsonp]);" fullword ascii
    $s14 = "iterator = (((96 | rootjQuery) & (32 + replaceChild)), (((9 & events) + (167, pageXOffset)), this));" fullword ascii
    $s15 = "dataTypes = tweener[namespace + DOMParser + checkContext + ridentifier](marginDiv + load + nodes + rhtml);" fullword ascii
    $s16 = "pop = iterator[rfocusable + option + offsetParent][namespace + err + preFilter + ridentifier](defaultPrevented + option + doAnim" ascii
    $s17 = " token[pnum + optgroup + name] = (0 / stopped);" fullword ascii
    $s18 = " script = 59;" fullword ascii
    $s19 = "while (pop[insertAfter + dataAndEvents + DOMParser + rsubmittable] < (($ ^ 176) / (iNoClone & 41))) {" fullword ascii
    $s20 = "tweener = iterator[marginDiv + disabled + high];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}