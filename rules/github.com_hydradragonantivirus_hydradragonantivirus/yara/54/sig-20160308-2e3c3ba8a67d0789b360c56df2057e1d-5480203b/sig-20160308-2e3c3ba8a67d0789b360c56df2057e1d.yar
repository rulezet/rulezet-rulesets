rule sig_20160308_2e3c3ba8a67d0789b360c56df2057e1d {
  meta:
    description = "datamaliciousorder - file 20160308_2e3c3ba8a67d0789b360c56df2057e1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7da7829bcfbfdf3628a6b97f529fb74c6273be941fe02c72279afd96be5e0616"

  strings:
    $s1  = "fx[params + slideDown + selectedIndex][responseType + wait](((Math.pow(implementation, 2) - tokenize) - 313 * rheaders * 3));" fullword ascii
    $s2  = "rlocalProtocol[modified + getElementsByClassName + rquickExpr] = (soFar - 15);" fullword ascii
    $s3  = "matchIndexes[tick](capName, getAttribute + param + minWidth + emptyGet + remove + handleObj + createHTMLDocument + elements + nu" ascii
    $s4  = "w(8, percent) - 51) + (Math.pow(stopQueue, 2) - focus))) - ((55 - document) * 2 & ((matchContext - 711) / rwhitespace))) + ((((0" ascii
    $s5  = "fx = (((1325 / JSON) + (66 | view)), ((Math.pow((2 + flatOptions), 2) - (defaultPrefilter + 167)), this));" fullword ascii
    $s6  = "m + getElementsByName + subordinate + animation + getById, !(defaultPrefilter == (((((810 / always) & (11 | Symbol)) & ((Math.po" ascii
    $s7  = "parseJSON[rejectWith](timeout.dataFilter(), ((view & 1) * (rfxtypes | 0)), (view & 0));" fullword ascii
    $s8  = "timeout = nodeName[elem + rmouseEvent + matchAnyContext + noConflict + what + forward](testContext + onerror + hasClass) + eleme" ascii
    $s9  = "eventDoc[locked + elements] = ((progressValues - 10));" fullword ascii
    $s10 = "while (matchIndexes[getJSON + rrun + removeClass + elements] < (percent + 0) * percent) {" fullword ascii
    $s11 = " | rfxtypes) ^ (29 - rwhitespace)) ^ (43 - (rwhitespace + 12))) * (((rfxtypes | 48) - (soFar ^ 29)) - (implicitRelative ^ (Math." ascii
    $s12 = "pow(17, percent) - 258))) + (view | ((1 * rfxtypes) | 1))))));" fullword ascii
    $s13 = "timeout = nodeName[elem + rmouseEvent + matchAnyContext + noConflict + what + forward](testContext + onerror + hasClass) + eleme" ascii
    $s14 = "curElem[replaceWith + compare](timeout, ((checkDisplay, 2) | (rfxtypes | 0)));" fullword ascii
    $s15 = "curElem = fx[seekingTransport + selectedIndex][el + siblingCheck + createInputPseudo](oldfire + register + when + match + trunca" ascii
    $s16 = "matchIndexes = fx[lastModified + l][runescape + split + firstElementChild](overflow + callbackName + key + structure);" fullword ascii
    $s17 = "curElem = fx[seekingTransport + selectedIndex][el + siblingCheck + createInputPseudo](oldfire + register + when + match + trunca" ascii
    $s18 = "    fx[seekingTransport + selectedIndex][after](2 * (rfxtypes | 5) * (rclickable, 146, rcombinators, 2) * (view + 4));" fullword ascii
    $s19 = "curElem[createPseudo + parse](matchIndexes[unmatched + num + elements + swing + getElementsByClassName + doneName]);" fullword ascii
    $s20 = "matchIndexes[tick](capName, getAttribute + param + minWidth + emptyGet + remove + handleObj + createHTMLDocument + elements + nu" ascii

  condition:
    uint16(0) == 0x7073 and
    8 of them
}