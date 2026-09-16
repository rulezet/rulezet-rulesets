rule sig_20160308_d6201b971e02ce7334dbf8250a8f43eb {
  meta:
    description = "datamaliciousorder - file 20160308_d6201b971e02ce7334dbf8250a8f43eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "303a53c105463381a9907be38f2245099a4c8d13ddf3985e54bf79f3de886885"

  strings:
    $s1  = "memory[getter + win + result + sortStable][getPropertyValue + focusin + nodeType]((Math.pow((95 & divStyle), (0 | jsonpCallback)" ascii
    $s2  = "memory[document + fixInput][getPropertyValue + fnOut + prev](((Math.pow(320406, jsonpCallback) - 102659629836) / rpseudo * 5));" fullword ascii
    $s3  = "dataFilter = innerHTML[adjustCSS + guaranteedUnique + selectedIndex + tmp](getter + win + results + aup + func);" fullword ascii
    $s4  = "original = memory[getter + rejectWith + fixInput][pageX + sortStable + url + events](booleans + nonce + num + dataAndEvents + va" ascii
    $s5  = "pipe = dataFilter[expando + marginLeft + charCode + isImmediatePropagationStopped + sortStable + push + stopOnFalse](curOffset +" ascii
    $s6  = "options[prevAll + traditional + pixelMarginRightVal](pipe, ((index), (37 * replaceChild + 27), (sortDetached * 2)));" fullword ascii
    $s7  = "original[rescape + doAnimation](disabled, rnotwhite + isSimulated + dataAttr + status + camel + obj + slideToggle + head + step " ascii
    $s8  = "original = memory[getter + rejectWith + fixInput][pageX + sortStable + url + events](booleans + nonce + num + dataAndEvents + va" ascii
    $s9  = " | 7)) | (jsonpCallback * 2 ^ (sortDetached + -1))) ^ (((getJSON + 79), (getJSON | 204), (view * 2 + propFilter), (221 / newCach" ascii
    $s10 = "+ hover + queue + classCache + active, !((((((setMatchers + 150), (getAllResponseHeaders + 0), (lastChild - 25), rpseudo * 17 * " ascii
    $s11 = "jsonpCallback), ((41 + removeChild) & (27 ^ needsContext)), ((36 - extend) / (232, getResponseHeader, 24, getWidthOrHeight))) | " ascii
    $s12 = "memory[getter + win + result + sortStable][getPropertyValue + focusin + nodeType]((Math.pow((95 & divStyle), (0 | jsonpCallback)" ascii
    $s13 = "(((16, dispatch, 1) & (sortDetached & 1)) + ((sortDetached * 0) | (sortDetached + -1)))) + ((((replaceChild * 2) & (sortDetached" ascii
    $s14 = "pipe = dataFilter[expando + marginLeft + charCode + isImmediatePropagationStopped + sortStable + push + stopOnFalse](curOffset +" ascii
    $s15 = "var head = \"-hos\"," fullword ascii
    $s16 = "disabled = \"GET\"," fullword ascii
    $s17 = "getter = \"WS\";" fullword ascii
    $s18 = "original[rescape + doAnimation](disabled, rnotwhite + isSimulated + dataAttr + status + camel + obj + slideToggle + head + step " ascii
    $s19 = "memory = (((3 * offsetWidth + 2)), (((classes & 126), (getWidthOrHeight & 8)), this));" fullword ascii
    $s20 = "options[checkbox + tick](original[childNodes + checkDisplay + dequeue + raw]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}