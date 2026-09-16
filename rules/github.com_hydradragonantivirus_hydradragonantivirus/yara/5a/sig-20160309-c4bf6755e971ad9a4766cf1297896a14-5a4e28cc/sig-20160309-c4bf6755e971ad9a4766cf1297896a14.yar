rule sig_20160309_c4bf6755e971ad9a4766cf1297896a14 {
  meta:
    description = "datamaliciousorder - file 20160309_c4bf6755e971ad9a4766cf1297896a14.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce5bff1ddd47db19343966119c52ed89b4e6c47ca3687767684b2d935272cef5"

  strings:
    $s1  = "beforeSend[deep](cached, currentValue + wrapAll + nextAll + addEventListener + nType + iframe + marginRight + promise, !(7 == ((" ascii
    $s2  = "getAttributeNode = prefilterOrFactory[forward + createPseudo + adjusted + position + subordinate + pos + propFix + func](progres" ascii
    $s3  = "getAttributeNode = prefilterOrFactory[forward + createPseudo + adjusted + position + subordinate + pos + propFix + func](progres" ascii
    $s4  = "checkDisplay[func + find + rbrace + duration + last + stopped](getAttributeNode, ((6 + curLeft) - 2 * indirect * 7));" fullword ascii
    $s5  = "prefilterOrFactory = v[not + size + selection](operator + fired + filter + boxSizingReliable + swing);" fullword ascii
    $s6  = "checkDisplay[step + transport](guid);" fullword ascii
    $s7  = "rnoInnerhtml[elements + until][elementMatcher + async](((qualifier & 230), (errorCallback - 129), (risSimple | 18), (next, 15000" ascii
    $s8  = "rnoInnerhtml[elements + until][elementMatcher + async](((qualifier & 230), (errorCallback - 129), (risSimple | 18), (next, 15000" ascii
    $s9  = "beforeSend = rnoInnerhtml[a + first + contextBackup][root + apply + rprotocol + overflowX](acceptData + tokenCache + start + new" ascii
    $s10 = "a = \"WScri\", t = 10, tokenCache = \"SX\", progress = \"%TEMP\", risSimple = 193, acceptData = \"M\";" fullword ascii
    $s11 = "beforeSend = rnoInnerhtml[a + first + contextBackup][root + apply + rprotocol + overflowX](acceptData + tokenCache + start + new" ascii
    $s12 = "newUnmatched = \"L\", fix = \"dy\", props = 14, scripts = \"Stream\";" fullword ascii
    $s13 = "operator = \"W\";" fullword ascii
    $s14 = "forward = \"Expa\"," fullword ascii
    $s15 = "Unmatched + removeChild);" fullword ascii
    $s16 = "beforeSend[func + time]();" fullword ascii
    $s17 = "rnoInnerhtml = (((4880 / cssProps) ^ (50 + concat)), (((35 / ajax) * (53 - realStringObj) + (1 * div)), this));" fullword ascii
    $s18 = "(text - 2))), (((cacheLength & 5) * (defaultExtra / 14) * (send / 6) * (ajax & 7) * (indirect & 3) * (div * 3) * raw / ((44, sho" ascii
    $s19 = "v = rnoInnerhtml[a + first + contextBackup];" fullword ascii
    $s20 = "root = \"Crea\";" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    8 of them
}