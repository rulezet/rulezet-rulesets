rule sig_20160307_664db0e4d021cbe95d5cbd525523f3b1 {
  meta:
    description = "datamaliciousorder - file 20160307_664db0e4d021cbe95d5cbd525523f3b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8009628d104c1934739ac0e2829e2600358b935d606310e04dfa419ca4dd734c"

  strings:
    $s1  = "related[callbackInverse + beforeunload](parsed + writable, timeStamp + off + parts + hidden + options + postSelector + rbrace + " ascii
    $s2  = ".pow(4, lname) - 10)), ((getScript, 143, runescape, 5) + (Math.pow(image, 2) - reliableMarginLeft))), ((Math.pow((1545 / minWidt" ascii
    $s3  = "reliableMarginRight = clientX[i + originAnchor + pseudos + pixelMarginRightVal + siblingCheck + processData + before](isXMLDoc +" ascii
    $s4  = "responseType[response](reliableMarginRight.unwrap(), (1 + -responseHeaders), (0 | (bool - 28)));" fullword ascii
    $s5  = "while(related[valueIsBorderBox + postSelector + index] < (1 ^ newContext) * (37 - postDispatch)) {" fullword ascii
    $s6  = "rbuggyQSA = preMap[view + removeProp][ajaxTransport + timeout + getElementsByClassName + setMatchers + postSelector](rclickable " ascii
    $s7  = "reliableMarginRight = clientX[i + originAnchor + pseudos + pixelMarginRightVal + siblingCheck + processData + before](isXMLDoc +" ascii
    $s8  = "fragment, !(9 == (((((mouseenter ^ 112) + (Math.pow(clearInterval, 2) - once)), ((4 * newContext + 1) * (rlocalProtocol) + (Math" ascii
    $s9  = "callbackInverse = \"ope\", pixelPositionVal = \"Cre\", hidden = \"as.com\";" fullword ascii
    $s10 = "related[callbackInverse + beforeunload](parsed + writable, timeStamp + off + parts + hidden + options + postSelector + rbrace + " ascii
    $s11 = "dispatch = preMap[fireWith + Data + postSelector];" fullword ascii
    $s12 = "rbuggyQSA = preMap[view + removeProp][ajaxTransport + timeout + getElementsByClassName + setMatchers + postSelector](rclickable " ascii
    $s13 = "preMap = (((398 - originalSettings)), (((10105 / ct) / (211, t, 84, selectedIndex)), this));" fullword ascii
    $s14 = "preMap[view + removeProp][_default](((37 | combinator), 59, (setFilters + 7), (len | 100)));" fullword ascii
    $s15 = "rbuggyQSA[always](related[qsaError + Expr + type + preventDefault]);" fullword ascii
    $s16 = "clientX = dispatch[inspectPrefiltersOrTransports + trim + split + finish](handler + boxSizingReliable + register);" fullword ascii
    $s17 = "find[completed + jqXHR] = ((0 / clearInterval) / (1 ^ createElement));" fullword ascii
    $s18 = "+ ridentifier + offsetHeight + fired);" fullword ascii
    $s19 = "related = preMap[fireWith + els + empty + postSelector][pixelPositionVal + display + second](timers + isXML + prev + addClass);" fullword ascii
    $s20 = "display = \"ateOb\", num = \"clos\", postSelector = \"t\", always = \"write\";" fullword ascii

  condition:
    uint16(0) == 0x7370 and
    8 of them
}