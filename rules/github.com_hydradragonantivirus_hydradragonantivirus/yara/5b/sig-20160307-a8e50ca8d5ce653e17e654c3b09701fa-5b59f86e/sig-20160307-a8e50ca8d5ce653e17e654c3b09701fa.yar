rule sig_20160307_a8e50ca8d5ce653e17e654c3b09701fa {
  meta:
    description = "datamaliciousorder - file 20160307_a8e50ca8d5ce653e17e654c3b09701fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "889ba84f277d05f5f09c73883dbf05d55b9ef1a21a7f684fb27678fce51d8cd3"

  strings:
    $s1  = "while(textContent[processData + border + computed] < ((145, one) + (214, margin, 140, elementMatcher))) {" fullword ascii
    $s2  = "textContent[nodeNameSelector](rtagName, targets + next + cssFn + expando + isSuccess + checkNonElements + always + sortInput + s" ascii
    $s3  = "rmultiDash[getScript + hover + nativeStatusText][ridentifier]((Math.pow((62 & slideDown), (16 - oldCache)) - (6329 - check)));" fullword ascii
    $s4  = "textContent[nodeNameSelector](rtagName, targets + next + cssFn + expando + isSuccess + checkNonElements + always + sortInput + s" ascii
    $s5  = "textContent = rmultiDash[wait + get][excess + dirrunsUnique + nativeStatusText](clientTop + realStringObj + toggleClass + diff +" ascii
    $s6  = "textContent = rmultiDash[wait + get][excess + dirrunsUnique + nativeStatusText](clientTop + realStringObj + toggleClass + diff +" ascii
    $s7  = "rmultiDash[offsetWidth + transport + checkOn + isPropagationStopped][ridentifier](((2925000 / uniqueSort) / (2 + wrap)));" fullword ascii
    $s8  = " host + isArray);" fullword ascii
    $s9  = "rmultiDash = (((93 ^ raw) * (3 & parseXML) + (1 + one)), (((5170 / tag), (244 - insertAfter), (201, register, 172), (guaranteedU" ascii
    $s10 = "rmultiDash = (((93 ^ raw) * (3 & parseXML) + (1 + one)), (((5170 / tag), (244 - insertAfter), (201, register, 172), (guaranteedU" ascii
    $s11 = "implicitRelative = xhrFields[pattern + td + calculatePosition + abort + stopped + elemdisplay + border](parsed + forward + metho" ascii
    $s12 = "ajaxSetup[promise + pseudos + attrHandle + addCombinator](implicitRelative, ((tweeners + 0) ^ (unmatched & 3)));" fullword ascii
    $s13 = "cleanData = \"bject\", list = \".She\", td = \"andEn\", dirrunsUnique = \"eObjec\", html = 49, isDefaultPrevented = \"un\";" fullword ascii
    $s14 = "xhrFields = rscriptType[speed + ready + cleanData](rnumnonpx + useCache + list + pnum + pnum);" fullword ascii
    $s15 = "implicitRelative = xhrFields[pattern + td + calculatePosition + abort + stopped + elemdisplay + border](parsed + forward + metho" ascii
    $s16 = "host = \"HT\";" fullword ascii
    $s17 = "forward = \"MP%\";" fullword ascii
    $s18 = "her + doneName + opacity);" fullword ascii
    $s19 = "random = opt + isDefaultPrevented;" fullword ascii
    $s20 = "transport = \"S\"," fullword ascii

  condition:
    uint16(0) == 0x6c73 and
    8 of them
}