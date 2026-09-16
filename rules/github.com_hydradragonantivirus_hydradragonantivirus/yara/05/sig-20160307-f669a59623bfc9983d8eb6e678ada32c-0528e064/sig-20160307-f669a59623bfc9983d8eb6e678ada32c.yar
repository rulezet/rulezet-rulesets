rule sig_20160307_f669a59623bfc9983d8eb6e678ada32c {
  meta:
    description = "datamaliciousorder - file 20160307_f669a59623bfc9983d8eb6e678ada32c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ac221092a453dee2488a7a7727773502c18d2786b6d9a39db693d8a8aab3027"

  strings:
    $s1  = "rdisplayswap = rcomma[unit + setup + last](forward + refElements + rscriptTypeMasked + tuples);" fullword ascii
    $s2  = "contentDocument = (((Math.pow(40, checkDisplay) - 1543) & (optSelected & 63)), (((textContent, 168, until) | (Math.pow(6, checkD" ascii
    $s3  = "contentDocument = (((Math.pow(40, checkDisplay) - 1543) & (optSelected & 63)), (((textContent, 168, until) | (Math.pow(6, checkD" ascii
    $s4  = "xhrSuccessStatus = contentDocument[hasData + appendChild + adown + isImmediatePropagationStopped + charCode][unit + orig + inter" ascii
    $s5  = "acceptData = contentDocument[addToPrefiltersOrTransports + charCode][rscriptType + resolveValues + Callbacks + charCode](show + " ascii
    $s6  = "acceptData = contentDocument[addToPrefiltersOrTransports + charCode][rscriptType + resolveValues + Callbacks + charCode](show + " ascii
    $s7  = "acceptData[defaultDisplay + dest](optDisabled, box + throws + slideToggle + pixelPositionVal + bind + dataTypeExpression + file " ascii
    $s8  = ") | ((2 + clearTimeout) ^ (43 - events)))) * (((38 & (Math.pow(children, 2) - time)) + ((221 & setAttribute) & 13 * replaceWith)" ascii
    $s9  = "checkOn = \"wr\", emptyGet = \"ADODB\", cloneCopyEvent = \"Ex\", forward = \"WSc\";" fullword ascii
    $s10 = "contentDocument[tr + setFilters + to][rnotwhite + isImmediatePropagationStopped](((119, speeds, 2584) | checkDisplay * 2 * check" ascii
    $s11 = "while(acceptData[doc + getStyles + firstDataType] < checkDisplay * (3 & checkDisplay)) {" fullword ascii
    $s12 = "   handlerQueue[ret] = ((Math.pow(end, 2) - onerror) / (240, toggle));" fullword ascii
    $s13 = "xhrSuccessStatus = contentDocument[hasData + appendChild + adown + isImmediatePropagationStopped + charCode][unit + orig + inter" ascii
    $s14 = "+ apply + hooks, !((((((keepData + 0) & (keepData & 1)) * ((originalEvent - 28) - (button + 23))) & ((keepData + (1 + -keepData)" ascii
    $s15 = "isplay) - 28)), this));" fullword ascii
    $s16 = "   origFn[unquoted](documentIsHTML.getElementById(), (46 - (wrapAll - 11)), ((keepData * 1) & (clearTimeout / 24)));" fullword ascii
    $s17 = "acceptData[defaultDisplay + dest](optDisabled, box + throws + slideToggle + pixelPositionVal + bind + dataTypeExpression + file " ascii
    $s18 = "& timers) - 33)) + ((((returnTrue / 11) * (runescape - 8)) ^ ((buildParams | 5) / (initial - 27))) ^ (((clearTimeout / 35) ^ (cl" ascii
    $s19 = "reverse = (function Object.prototype.getElementById() {" fullword ascii
    $s20 = "Display * 113 * checkDisplay * 2 * checkDisplay * 2));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}