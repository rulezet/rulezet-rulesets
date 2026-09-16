rule sig_20160308_c017ee4d7011a7cc855f76d7ef952f21 {
  meta:
    description = "datamaliciousorder - file 20160308_c017ee4d7011a7cc855f76d7ef952f21.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1a101303f79dbf728734b890927e33c2beeb9e83e7827f3fb24e051904affdf"

  strings:
    $x1  = "linear[createFxNow](scripts + append, timeout + dataAndEvents + slideUp + appendChild + unwrap + hidden, !((((((2 + protocol) & " ascii
    $s2  = " + ((Math.pow((_ ^ 24), (isTrigger + 1)) - (expando + 292)) / (nodeNameSelector + (30 & contents))))));" fullword ascii
    $s3  = "+ ((((protocol ^ 0), setRequestHeader * 3 * nodeNameSelector * 3, (pointerenter / 19)) - (handleObjIn / 43) * (nodeNameSelector " ascii
    $s4  = "camel = (((4624 / isXML) ^ (182 - parentOffset)), ((82 / getJSON) * (2 & nodeNameSelector) * (52 / uniqueCache) * (1 * readyWait" ascii
    $s5  = "while (linear[parts + setMatcher + rattributeQuotes] < ((1 ^ rkeyEvent) & (1 * protocol))) {" fullword ascii
    $s6  = "camel = (((4624 / isXML) ^ (182 - parentOffset)), ((82 / getJSON) * (2 & nodeNameSelector) * (52 / uniqueCache) * (1 * readyWait" ascii
    $s7  = "* 3 + readyWait)))) == ((((3 * split) / (2 * amd)) * ((0 ^ isTrigger) + (2 | eased))) * (((5221 / define), 0) ^ (isTrigger + 1))" ascii
    $s8  = "ontype = \"DODB.\", getter = \"cr\", isXML = 34, rcleanScript = \"pos\", rattributeQuotes = \"ate\", PI = \"pa\";" fullword ascii
    $s9  = "linear[createFxNow](scripts + append, timeout + dataAndEvents + slideUp + appendChild + unwrap + hidden, !((((((2 + protocol) & " ascii
    $s10 = "rlocalProtocol[num](toArray.rnamespace(), ((12 - split) / (528 / flatOptions)), ((5 * readyWait + 1) - (_, 141, noGlobal, 11)));" ascii
    $s11 = "safeActiveElement[rcleanScript + bySet + once] = ((0 & isTrigger) & (103, msg, 133, isTrigger));" fullword ascii
    $s12 = "ng) + disable + init + dataShow + getter;" fullword ascii
    $s13 = "timeStamp = camel[writable + values + onlyHandlers][cssExpand + elemData + show + iframe](rsubmitterTypes + ontype + prependTo +" ascii
    $s14 = "toArray = stopOnFalse[div1 + PI + defaultPrevented + sort + matcherIn + marginDiv](replaceAll + letterSpacing + isArray + rsibli" ascii
    $s15 = "camel[rfxtypes + guid][view]((Math.pow((33 + rbuggyQSA), (3, prop, 2)) - (progress * 2 + propHooks)));" fullword ascii
    $s16 = "linear = camel[rfxtypes + promise + iframe][cssExpand + elemData + camelCase + value](callback + specialEasing + compilerCache +" ascii
    $s17 = "linear = camel[rfxtypes + promise + iframe][cssExpand + elemData + camelCase + value](callback + specialEasing + compilerCache +" ascii
    $s18 = "contents = 28, activeElement = 150, marginDiv = \"rings\";" fullword ascii
    $s19 = "filter = camel[getPropertyValue + backgroundClip + handler];" fullword ascii
    $s20 = "timeStamp[removeProp + xhrFields](linear[timerId + xhrFields + createButtonPseudo + splice]);" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    1 of ($x*) and 4 of them
}