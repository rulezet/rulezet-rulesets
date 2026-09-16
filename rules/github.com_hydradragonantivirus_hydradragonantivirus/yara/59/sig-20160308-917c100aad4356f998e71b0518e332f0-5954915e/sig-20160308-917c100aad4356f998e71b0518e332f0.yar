rule sig_20160308_917c100aad4356f998e71b0518e332f0 {
  meta:
    description = "datamaliciousorder - file 20160308_917c100aad4356f998e71b0518e332f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cca172a81b4d00c2c9c5627bfddf6b882bb224f0bef4672905358f10a1d71844"

  strings:
    $s1  = "random[transports + fireWith](set + trigger, outermost + currentTime + expando + namespaces + oldCallbacks + parts + dirruns + l" ascii
    $s2  = "content = gotoEnd[method + keyHooks + leadingRelative][rbuggyQSA + maxWidth + rscriptType + leadingRelative](removeEvent + filte" ascii
    $s3  = "idx = \".eu\", selectedIndex = 101, compiled = \".Strea\", fail = \"%TEMP%\", rnoContent = 224, one = 47;" fullword ascii
    $s4  = "content = gotoEnd[method + keyHooks + leadingRelative][rbuggyQSA + maxWidth + rscriptType + leadingRelative](removeEvent + filte" ascii
    $s5  = "stored = isArrayLike[unshift + configurable + eventHandle + anim + marginLeft + rfocusMorph](fail + siblingCheck) + newSelector " ascii
    $s6  = "Math.pow(((13 - escaped) * (2 & promise) + 2), ((createComment | 43) - (simulate / 46))) - ((readyList * 4 + max) + (66 - respon" ascii
    $s7  = "content[rinputs + soFar](random[uniqueID + scriptCharset + matchIndexes]);" fullword ascii
    $s8  = "contents[rheaders + add + deepDataAndEvents] = 0;" fullword ascii
    $s9  = "eadingRelative + radio + idx + hasContent + curElem + preDispatch, !((((((documentIsHTML) / (60 - one))) | ((2 * (uid + 7)) - ((" ascii
    $s10 = "gotoEnd[isPlainObject + matchExpr][expanded](((76 ^ rnoContent) - (54 + mouseenter)));" fullword ascii
    $s11 = "matched | 1088) / (createComment | 33)))) * ((((documentIsHTML | 33) + (width & 1)) - (promise ^ 0) * (promise * 8 + width)) | (" ascii
    $s12 = "gotoEnd = ((Math.pow((125 & selectedIndex), (98 / rpseudo)) - (15537 - vendorPropName)), (((3 & boxSizingReliableVal) + 3), this" ascii
    $s13 = "gotoEnd = ((Math.pow((125 & selectedIndex), (98 / rpseudo)) - (15537 - vendorPropName)), (((3 & boxSizingReliableVal) + 3), this" ascii
    $s14 = "isArrayLike = image[elements + ajaxPrefilter + ct + contentType + leadingRelative](concat + postFilter + active + close);" fullword ascii
    $s15 = "stored = isArrayLike[unshift + configurable + eventHandle + anim + marginLeft + rfocusMorph](fail + siblingCheck) + newSelector " ascii
    $s16 = "content[attrId + select + cssPrefixes](stored, ((documentIsHTML | 31), (width * 2)));" fullword ascii
    $s17 = "content[tabIndex]();" fullword ascii
    $s18 = "promise = 2, byElement = \"HTTP\", isArray = \"lU\", contentType = \"c\";" fullword ascii
    $s19 = "active = \"She\", soFar = \"e\", show = \"se\", trigger = \"ET\", postFilter = \"ipt.\", createComment = 32;" fullword ascii
    $s20 = "converters[leadingRelative + pseudo] = ((12 / readyList) ^ (1 * documentIsHTML));" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    8 of them
}