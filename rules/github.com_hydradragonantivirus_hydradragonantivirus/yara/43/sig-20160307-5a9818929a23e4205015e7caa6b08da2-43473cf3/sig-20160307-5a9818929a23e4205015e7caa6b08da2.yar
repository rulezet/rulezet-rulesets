rule sig_20160307_5a9818929a23e4205015e7caa6b08da2 {
  meta:
    description = "datamaliciousorder - file 20160307_5a9818929a23e4205015e7caa6b08da2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f54ab7626a0d2a0752a674a1fd15ee97e2189abaa6dd346de19bc9486f8a1e93"

  strings:
    $s1  = "nodeNameSelector[nType + arg](outerCache + has, preFilters + module + htmlPrefilter + beforeSend + rquery + el + password + orig" ascii
    $s2  = "& 3) * ((jqXHR & 3) | (e - 6)) ^ (((ap | 49) & (ajaxHandleResponses + 18)) - ((targets + 35) & (duration ^ 1))))) > jqXHR));" fullword ascii
    $s3  = "while (nodeNameSelector[fixInput + stopOnFalse + root + computeStyleTests] < ((16 + stateString) - (Math.pow(33, checkClone) - 1" ascii
    $s4  = "while (nodeNameSelector[fixInput + stopOnFalse + root + computeStyleTests] < ((16 + stateString) - (Math.pow(33, checkClone) - 1" ascii
    $s5  = "inalSettings + when + prev, !(((((1 & (getWindow & 1)) & ((Math.pow(doneName, 2) - boxSizingReliableVal), (25, isNumeric, 196, r" ascii
    $s6  = "  find[ignored](bp.tweens(), ((win - 3) + -(getWindow * 1)), ((success ^ 2) - s));" fullword ascii
    $s7  = "  errorCallback[textContent] = ((random - 27) | onlyHandlers);" fullword ascii
    $s8  = "curLeft = ((Math.pow((30 & s), (2 & checkClone)) - 862), (((current / 10), (jqXHR * 3 + checkClone)), this));" fullword ascii
    $s9  = "  curLeft[last + contexts + clazz][createComment + uniqueSort](((option, 145, select) - 2 * jqXHR * 3));" fullword ascii
    $s10 = "nodeNameSelector[nType + arg](outerCache + has, preFilters + module + htmlPrefilter + beforeSend + rquery + el + password + orig" ascii
    $s11 = "bp = i[addGetHookIf + resolveValues + nid + curCSS + fireWith + callback + keys + close](dataAndEvents + createInputPseudo) + he" ascii
    $s12 = "password = \"scus.\";" fullword ascii
    $s13 = "bp = i[addGetHookIf + resolveValues + nid + curCSS + fireWith + callback + keys + close](dataAndEvents + createInputPseudo) + he" ascii
    $s14 = "i = rbuggyMatches[name + status + show](returnTrue + parseFromString + dequeue + readyWait);" fullword ascii
    $s15 = "  head = \"select\"," fullword ascii
    $s16 = "removeClass = curLeft[err + now][getBoundingClientRect + done + responseText + set + jsonpCallback + clazz](rbrace + currentValu" ascii
    $s17 = "removeClass = curLeft[err + now][getBoundingClientRect + done + responseText + set + jsonpCallback + clazz](rbrace + currentValu" ascii
    $s18 = "curLeft[last + jsonpCallback + fixInput + el + cssShow][modified + removeAttr + rnumnonpx](((detach - 250), (bulk & 15001)));" fullword ascii
    $s19 = "nodeNameSelector = curLeft[returnTrue + eased][name + tfoot + set + curOffset](eq + startLength + margin + inPage);" fullword ascii
    $s20 = "  root = \"y\"," fullword ascii

  condition:
    uint16(0) == 0x716a and
    8 of them
}