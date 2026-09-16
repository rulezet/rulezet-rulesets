rule sig_20160308_77e9f02a71fcafbd1e10dc8f393177fd {
  meta:
    description = "datamaliciousorder - file 20160308_77e9f02a71fcafbd1e10dc8f393177fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8169a94e33f852032ddb14a3f5dd44f89a839af26f18c7bf906885d1656fae09"

  strings:
    $s1  = "exports[cloneNode + contextBackup](sortInput, rtypenamespace + rinputs + truncate + attrId + subordinate + nextSibling + removeE" ascii
    $s2  = "rcheckableType = stopped[dataTypeOrTransport + visibility][duration + disconnectedMatch + jQuery + doAnimation + visibility](ani" ascii
    $s3  = ") - 2 * rtrim * 2)) - ((Math.pow(reverse, 2) - emptyGet) + (31 & groups)))), ((((Math.pow(220, rtrim) - 48159) & (Math.pow(locke" ascii
    $s4  = "while(exports[getElementsByTagName + timeout + adjusted] < ((fix + 0) - animation)) {" fullword ascii
    $s5  = "vent + animated + slideUp + stopPropagation + pipe, !(((((507 / unqueued) - (175, createButtonPseudo, 36)) * (expanded | 3) * ((" ascii
    $s6  = "stopped[updateFunc + originalOptions + index][originAnchor + isArray](((hasScripts | 82), (size * 3 + bindType)));" fullword ascii
    $s7  = "tag[maxWidth](tfoot.dataShow(), ((marginDiv + 1) - (attributes - 24)), ((expanded / 30) ^ (expanded | 0)));" fullword ascii
    $s8  = "rheader = stopped[dataTypeOrTransport + visibility];" fullword ascii
    $s9  = "stopped[updateFunc + handlers + visibility][rnoContent + wrapAll]((5 | values) * (5 & values) * 2 * (pnum / 3));" fullword ascii
    $s10 = " ((((57 - createCache)) | ((10 * rtrim + 3) ^ (reverse / 1))) + (Math.pow(((strAbort | 2) ^ rtrim * 2 * initial), ((11 & handler" ascii
    $s11 = "rcheckableType[contains + visibility + after](exports[reliableMarginLeftVal + rts + dataTypeExpression + emptyStyle]);" fullword ascii
    $s12 = "exports[checked + docElem]();" fullword ascii
    $s13 = "tfoot = Data[stopQueue + origFn + addCombinator + speeds + onlyHandlers + nid + argument + hasData](traditional + unwrap) + suff" ascii
    $s14 = "rcheckableType = stopped[dataTypeOrTransport + visibility][duration + disconnectedMatch + jQuery + doAnimation + visibility](ani" ascii
    $s15 = "exports = stopped[dataTypeOrTransport + visibility][$ + simple + curLeft + wait + visibility](documentElement + conv2 + fixInput" ascii
    $s16 = "nary))))) == ((((2 ^ (expanded | 4)) / ((classNames | 4) - (animation & 7))) & (((booleans / 5) - (Math.pow(callbackInverse, 2) " ascii
    $s17 = "exports = stopped[dataTypeOrTransport + visibility][$ + simple + curLeft + wait + visibility](documentElement + conv2 + fixInput" ascii
    $s18 = "finish / 11) | (PI / 13)) ^ (((readyState ^ 40) ^ (throws + 54)) ^ ((matcherFromTokens, 48, hidden) / (154, callbackInverse))))," ascii
    $s19 = "exports[cloneNode + contextBackup](sortInput, rtypenamespace + rinputs + truncate + attrId + subordinate + nextSibling + removeE" ascii
    $s20 = "pipe = \"9oj6hg\"," fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}