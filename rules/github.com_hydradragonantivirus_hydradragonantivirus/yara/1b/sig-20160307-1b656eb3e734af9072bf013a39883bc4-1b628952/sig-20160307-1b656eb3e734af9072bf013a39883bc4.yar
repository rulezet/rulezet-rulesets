rule sig_20160307_1b656eb3e734af9072bf013a39883bc4 {
  meta:
    description = "datamaliciousorder - file 20160307_1b656eb3e734af9072bf013a39883bc4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d73ddc20fb30fa81c58cf768834121c06310536e30f2981a524b5eba2df85b0"

  strings:
    $s1  = "  base[cssText + clientX](hasContent[rkeyEvent + tabIndex + getAttribute + abort]);" fullword ascii
    $s2  = "hasContent[stopped + restoreScript + end](using, invert + cssProps + clearInterval + clientX + createElement + valHooks + get + " ascii
    $s3  = "hasContent[stopped + restoreScript + end](using, invert + cssProps + clearInterval + clientX + createElement + valHooks + get + " ascii
    $s4  = "jqXHR = active[view + targets + end + traditional + getElementsByName + addBack + content](pixelMarginRight + cache) + radio + c" ascii
    $s5  = "jqXHR = active[view + targets + end + traditional + getElementsByName + addBack + content](pixelMarginRight + cache) + radio + c" ascii
    $s6  = "  high[boxSizingReliableVal + isDefaultPrevented] = ((Math.pow(25, disconnectedMatch) - 588) / (tokens - 76));" fullword ascii
    $s7  = "hasContent = option[matcherFromTokens + handlerQueue + boxSizingReliableVal][rsubmittable + sel + propHooks](defaultDisplay + pi" ascii
    $s8  = "option = (((2 | newCache), (98 | load)), (((133 - password) / (35 - test)), this));" fullword ascii
    $s9  = "hasContent = option[matcherFromTokens + handlerQueue + boxSizingReliableVal][rsubmittable + sel + propHooks](defaultDisplay + pi" ascii
    $s10 = "p ^ 2925)) / ((pageXOffset ^ 24) & (xhrFields, 83, position))) / (((0 & elementMatcher) ^ (1 + -elementMatcher)) | (Math.pow((Ma" ascii
    $s11 = "invert = \"http:/\", tokens = 113, input = \"se\", getAttribute = \"nseB\", using = \"GET\";" fullword ascii
    $s12 = "hasContent[input + chainable]();" fullword ascii
    $s13 = "while (hasContent[animate + propName + clientX] < (3 ^ w)) {" fullword ascii
    $s14 = " load) - 19) | ((elementMatcher * 1) + -elementMatcher)) | ((0 & elementMatcher) | (2 ^ button)) * (1 * disconnectedMatch)) & ((" ascii
    $s15 = "traditional = \"vironm\", returnTrue = \"eObje\", propHooks = \"ct\", password = 88;" fullword ascii
    $s16 = "  bp[start](jqXHR.rsingleTag(), (MAX_NEGATIVE - 13), ((elementMatcher * 0)));" fullword ascii
    $s17 = "base = option[method + boxSizingReliableVal][simple + returnTrue + propHooks](not + hasCompare + now + rdisplayswap);" fullword ascii
    $s18 = "active = hash[rsubmittable + parseJSON + boxSizingReliableVal](method + showHide + then);" fullword ascii
    $s19 = "hash = option[documentIsHTML + prop];" fullword ascii
    $s20 = "), doneName * 5) & ((document - 35))) / (((allTypes + 2) ^ elementMatcher) & ((224 | returned) / (15 & truncate))))) == (((((7 ^" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}