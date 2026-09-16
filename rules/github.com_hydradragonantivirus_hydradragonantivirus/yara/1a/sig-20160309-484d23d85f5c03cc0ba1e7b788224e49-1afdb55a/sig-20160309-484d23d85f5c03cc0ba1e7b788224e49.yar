rule sig_20160309_484d23d85f5c03cc0ba1e7b788224e49 {
  meta:
    description = "datamaliciousorder - file 20160309_484d23d85f5c03cc0ba1e7b788224e49.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f1c75f05603db0401694e8f8b3109f3cb687c33aaf33704d0601349550fe8f2"

  strings:
    $x1  = "fadeOut[fireWith + rcheckableType](rbuggyQSA, responseContainer + responseHeadersString + htmlPrefilter + inPage + next + setMat" ascii
    $s2  = "fnOver = letter[args + scripts + className][r20 + fx + hidden + seekingTransport + rcomma](evt + base + getter);" fullword ascii
    $s3  = " (0 ^ letterSpacing)) + (1 & (keepScripts * 1))) / ((((isNumeric | 160) | (password / 15)), ((origCount ^ 21)), ((self & 244) + " ascii
    $s4  = "letter = (((Math.pow(6, addHandle) - 28) & (dir - 25)), ((keepScripts * (416 / namespace)), this));" fullword ascii
    $s5  = "letter[rtagName + box][cur + ignored + callbackExpect]((Math.pow(keys * 2 * addHandle * 137 * keys * 2, (addHandle | 0)) - addHa" ascii
    $s6  = "fadeOut = letter[args + rclickable][addToPrefiltersOrTransports + removeAttribute + groups + rcomma](condense + argument + fail " ascii
    $s7  = "deepDataAndEvents[whitespace](pipe.id(), ((0 / tokenCache) / (14 ^ keyCode)), ((10 - tokenCache) / (2 + define)));" fullword ascii
    $s8  = " 9298) / (keys * 16 + keepScripts)), (47 * v / (47 & readyWait)), (188, func, 2) * (letterSpacing | 2)))) > define));" fullword ascii
    $s9  = "fadeOut = letter[args + rclickable][addToPrefiltersOrTransports + removeAttribute + groups + rcomma](condense + argument + fail " ascii
    $s10 = "letter[rtagName + box][cur + ignored + callbackExpect]((Math.pow(keys * 2 * addHandle * 137 * keys * 2, (addHandle | 0)) - addHa" ascii
    $s11 = "fnOver[num + aup + transport + docElem + isDefaultPrevented](pipe, 2);" fullword ascii
    $s12 = "view = letter[sort + getElementsByName];" fullword ascii
    $s13 = "ndle * 2 * statusCode * 3 * triggered * 2 * getElementById));" fullword ascii
    $s14 = "fadeOut[fireWith + rcheckableType](rbuggyQSA, responseContainer + responseHeadersString + htmlPrefilter + inPage + next + setMat" ascii
    $s15 = "password = 255;" fullword ascii
    $s16 = "pipe = assert[contextBackup + unbind + key + toggleClass + computed + fragment](submit + insertBefore + escapedWhitespace + clos" ascii
    $s17 = "pipe = assert[contextBackup + unbind + key + toggleClass + computed + fragment](submit + insertBefore + escapedWhitespace + clos" ascii
    $s18 = "var getter = \"ream\"," fullword ascii
    $s19 = "count = fadeOut[charCode + includeWidth + num + setOffset + rbuggyMatches];" fullword ascii
    $s20 = "assert = view[lastModified + serializeArray + initialInUnit](rtagName + mozMatchesSelector + expando + marginRight);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}