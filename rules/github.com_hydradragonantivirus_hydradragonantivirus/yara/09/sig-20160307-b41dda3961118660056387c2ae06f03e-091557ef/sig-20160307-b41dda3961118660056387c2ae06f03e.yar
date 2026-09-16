rule sig_20160307_b41dda3961118660056387c2ae06f03e {
  meta:
    description = "datamaliciousorder - file 20160307_b41dda3961118660056387c2ae06f03e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de04d4a5458804a476d1c97b012bbe18af57ede893d8fdba6f764eb4e0b6e9a0"

  strings:
    $x1  = "map[matched](startTime + jsonp, rootjQuery + rrun + globalEventContext + raw + curElem + currentTarget + contentDocument + andSe" ascii
    $s2  = "map = throws[detach + fadeIn + activeElement][invert + preventDefault + push + col + parentNode](winnow + getScript + rjsonp + s" ascii
    $s3  = "map = throws[detach + fadeIn + activeElement][invert + preventDefault + push + col + parentNode](winnow + getScript + rjsonp + s" ascii
    $s4  = "add = dataFilter[setRequestHeader + blur + optionSet + rscriptType + optionSet](nodeName + ignored + match + removeProp);" fullword ascii
    $s5  = "currentValue[script + ofType + qsa + maxIterations](code, ((siblingCheck ^ 2) & (emptyGet & 3)));" fullword ascii
    $s6  = ".pow(((97 - converters) - (24 ^ _queueHooks)), (25 - replaceAll)) - (2 * letterSpacing * 2 * unbind + (556 - preMap)))) - (Math." ascii
    $s7  = "throws[rmargin + owner + optionSet][specialEasing + optgroup](((getElementById / 23), (valueIsBorderBox + 68), (hasCompare ^ 163" ascii
    $s8  = "while(map[preventDefault + rheader + addEventListener] < ((3 & emptyGet) + 1)) {" fullword ascii
    $s9  = "throws[rmargin + owner + optionSet][specialEasing + optgroup](((getElementById / 23), (valueIsBorderBox + 68), (hasCompare ^ 163" ascii
    $s10 = "pow((Math.pow((Math.pow(2 * letterSpacing * 7, letterSpacing) - 5 * always * 3 * always), (1 * letterSpacing)) - ((3294 & split)" ascii
    $s11 = "hild), (10 | always)))) - (Math.pow((3 + siblingCheck), (127, letterSpacing)) - (1 ^ firing)) * ((620 - doScroll) / (51 - b)) * " ascii
    $s12 = "currentValue[pushStack](map[isReady + resolveContexts + arg + script + fireWith + orig + rbrace]);" fullword ascii
    $s13 = "appendChild[curLeft + filter] = ((elemLang & 0) | (rcheckableType - 28));" fullword ascii
    $s14 = "wait = \".scr\", orig = \"Bo\";" fullword ascii
    $s15 = "currentValue = throws[rmargin + hooks + activeElement][timeout + rscriptType + optionSet](cors + width + funescape + fireWith + " ascii
    $s16 = "currentValue = throws[rmargin + hooks + activeElement][timeout + rscriptType + optionSet](cors + width + funescape + fireWith + " ascii
    $s17 = "rjsonp = \"XM\", match = \"ipt.Sh\", setRequestHeader = \"Cre\";" fullword ascii
    $s18 = " + matchIndexes + amd + ignored + wait;" fullword ascii
    $s19 = "throws = (((32 | lastChild) + (211, b)), ((1 * (always ^ 0)), this));" fullword ascii
    $s20 = "currentValue[speed + arg]();" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    1 of ($x*) and 4 of them
}