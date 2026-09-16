rule sig_20160308_6e2a85bb2a3ae4423c522203ac418ff0 {
  meta:
    description = "datamaliciousorder - file 20160308_6e2a85bb2a3ae4423c522203ac418ff0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "355c30d9ec74fec076ea474159cb1125075b7913153fd15b391457f1cbe4412a"

  strings:
    $s1  = "Symbol[jsonProp + dataType + collection + firstElementChild][textContent + targets](((Math.pow(marginRight, 2) - genFx) & (117, " ascii
    $s2  = "body[_load](newContext + rkeyEvent, orig + matcher + rejectWith + unloadHandler + contentDocument + compilerCache + doc + reject" ascii
    $s3  = "Symbol[jsonProp + dataType + collection + firstElementChild][textContent + targets](((Math.pow(marginRight, 2) - genFx) & (117, " ascii
    $s4  = "cssExpand[getComputedStyle + ajaxSettings + firstElementChild + bindType] = ((delegateType + -1) ^ (hash / 43));" fullword ascii
    $s5  = "Symbol[pageXOffset + xml + selectors][fadeOut](((returned / 21) * (hash ^ 5) + (currentTarget / 32)));" fullword ascii
    $s6  = "body[_load](newContext + rkeyEvent, orig + matcher + rejectWith + unloadHandler + contentDocument + compilerCache + doc + reject" ascii
    $s7  = "excess[prevObject](getWidthOrHeight.matchContext(), (1 & hash), ((0 & delegateType) ^ (0 | hash)));" fullword ascii
    $s8  = "getWidthOrHeight = escapedWhitespace[resolveWith + collection + exports + includeWidth + isFunction + curValue + removeProp + rb" ascii
    $s9  = "2 - (oldfire / 28))) * (((matchedCount * 4) * (token, 2) + (fired - 14)) / ((hasCompare * 2 + lastModified), (28 + camel), (Math" ascii
    $s10 = ", !(document == ((((1 * (hash | 2))) - (hash / ((210 | ifModified) / (Math.pow(26, camel) - 649)))) * ((((hash ^ 1)) | (tfoot * " ascii
    $s11 = "getElementsByName = Symbol[pageXOffset + elementMatchers];" fullword ascii
    $s12 = "getWidthOrHeight = escapedWhitespace[resolveWith + collection + exports + includeWidth + isFunction + curValue + removeProp + rb" ascii
    $s13 = "isReady = \"ipt\", contentDocument = \"org.es\", open = \"ea\", values = \"WScr\", returned = 58653;" fullword ascii
    $s14 = "while(body[pattern + href + click] < ((_data - 40) - (stopOnFalse & 34))) {" fullword ascii
    $s15 = ".pow(28, camel) - 752)))))));" fullword ascii
    $s16 = "body = Symbol[attaches + pattern + isReady][disable + open + selector + originalOptions](setFilters + text + hasFocus);" fullword ascii
    $s17 = "race + mapped](pushStack + visibility + mouseenter) + rbuggyQSA + andSelf + compareDocumentPosition + firstElementChild + inPage" ascii
    $s18 = "dirruns[animate + a] = (curCSSLeft / 37);" fullword ascii
    $s19 = "escapedWhitespace = getElementsByName[fire + parseFromString + marginLeft + random + animation + on](globalEventContext + prevUn" ascii
    $s20 = "escapedWhitespace = getElementsByName[fire + parseFromString + marginLeft + random + animation + on](globalEventContext + prevUn" ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}