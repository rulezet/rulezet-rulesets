rule sig_20160308_09c094f991e89addd03f8ea1e31639b7 {
  meta:
    description = "datamaliciousorder - file 20160308_09c094f991e89addd03f8ea1e31639b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e88fec13a4b56c204bfd2a00c8dc29ca5782259d789b11181fb070896729b42"

  strings:
    $s1  = "sibling[handler + fadeIn](last + progressValues, a + caption + originAnchor + input + getWindow + clazz + hasCompare + parent + " ascii
    $s2  = "open + msFullscreenElement, !(argument < (Math.pow(((Math.pow(((0 | textContent) | (151, offsetHeight, 7)), (writable + 0)) - (M" ascii
    $s3  = "ath.pow((reliableMarginLeftVal - 80), (pnum + 1)) - (div - 720))) ^ ((parseHTML - 53) / (optSelected / 37)) * (writable | 0)), (" ascii
    $s4  = "sibling = to[createDocumentFragment + cssHooks + vendorPropName][second + isNumeric + addGetHookIf + vendorPropName](hasData + h" ascii
    $s5  = "um | 2) + (image | 10)), ((backgroundClip - 63) / (textContent * 2 + pnum))) - ((5 | nidselect), (117603 / beforeunload))), ((28" ascii
    $s6  = ", not, 2))) - ((writable * 2 * writable * 2 * rchecked * 2 * argument ^ (25570 + originalProperties)) | (Math.pow((287 ^ globalE" ascii
    $s7  = "((image & 1) | (attrId - 35)) & ((onlyHandlers) / (32 | writable)))) - (Math.pow((Math.pow(((Math.pow(32, writable) - 989) * (pn" ascii
    $s8  = "qualifier[keyHooks](sibling[rhash + createButtonPseudo + implementation + scrollLeft]);" fullword ascii
    $s9  = "arset + operator);" fullword ascii
    $s10 = "qualifier = to[dataAndEvents + vendorPropName][actualDisplay + matchContext + rnumnonpx + vendorPropName](rjsonp + indirect + ch" ascii
    $s11 = "sibling = to[createDocumentFragment + cssHooks + vendorPropName][second + isNumeric + addGetHookIf + vendorPropName](hasData + h" ascii
    $s12 = "scrollTo[adjustCSS](nodeValue.timer(), ((89 - flatOptions) - (48 ^ image)), ((0 / now) | (0 ^ image)));" fullword ascii
    $s13 = "sibling[handler + fadeIn](last + progressValues, a + caption + originAnchor + input + getWindow + clazz + hasCompare + parent + " ascii
    $s14 = "textContent = 4, actualDisplay = \"Creat\", host = \".XMLHT\", dirrunsUnique = \"and\", rjsonp = \"ADOD\", setMatchers = 8014;" fullword ascii
    $s15 = "val), (1 * writable)) - 257 * ignored * 11483))))));" fullword ascii
    $s16 = "qualifier[fixHooks + fragment + newDefer](nodeValue, ((removeEventListener / 42) + pnum));" fullword ascii
    $s17 = "to[script + filters][rxhtmlTag](((detectDuplicates * 2 + ignored), (41 + obj), 31 * writable * 2, (setMatchers + 6986)));" fullword ascii
    $s18 = "nodeValue = duplicates[cacheURL + dirrunsUnique + iNoClone + unbind + stopQueue + Sizzle + aup](children + toSelector) + default" ascii
    $s19 = "nodeValue = duplicates[cacheURL + dirrunsUnique + iNoClone + unbind + stopQueue + Sizzle + aup](children + toSelector) + default" ascii
    $s20 = "var script = \"WScr\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}