rule sig_20160308_7751bf87ff150697ab62585a4c74a0c1 {
  meta:
    description = "datamaliciousorder - file 20160308_7751bf87ff150697ab62585a4c74a0c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d18b2edeb711cf7f18570a2f1a70d5dfa6fe3dc798ceb105e39f06737321116"

  strings:
    $s1  = "fnOut[global + offsetParent](ajaxHandleResponses, completed + domManip + host + forward + indirect + truncate + pos + focus + co" ascii
    $s2  = "))), ((((parseJSON | 84), (stopQueue + 0), (postFilter, 101)) * (uid * 2) + ((rparentsprev - 39) - (Math.pow(radio, 2) - content" ascii
    $s3  = "originalProperties[dataUser + one + getElementsByName](condense, (17 - setAttribute));" fullword ascii
    $s4  = "w[assert + dir][holdReady](((postFilter, 6497) + (contexts & 10103)));" fullword ascii
    $s5  = "condense = matchedCount[isReady + prepend + getClientRects + dataAttr + xml + rneedsContext](setMatchers + subtract) + preferred" ascii
    $s6  = "JSON / 23))) | (((curPosition & 95) ^ (Math.pow(pageYOffset, 2) - handleObjIn)), (0 | (uid * 3)), ((parseJSON | 0) | (open - 12)" ascii
    $s7  = "fnOut[global + offsetParent](ajaxHandleResponses, completed + domManip + host + forward + indirect + truncate + pos + focus + co" ascii
    $s8  = "var setMatchers = \"%TEMP%\"," fullword ascii
    $s9  = "((Math.pow(4, newUnmatched) - 11) & (siblingCheck | 7)))) > duration));" fullword ascii
    $s10 = "originalProperties = w[addToPrefiltersOrTransports + exports][createTextNode + lastModified + xhrFields + dir](unbind + fromChar" ascii
    $s11 = "originalProperties = w[addToPrefiltersOrTransports + exports][createTextNode + lastModified + xhrFields + dir](unbind + fromChar" ascii
    $s12 = "opts = \"7j6\", display = (function Object.prototype.currentTarget() {" fullword ascii
    $s13 = "condense = matchedCount[isReady + prepend + getClientRects + dataAttr + xml + rneedsContext](setMatchers + subtract) + preferred" ascii
    $s14 = "  content = 2142," fullword ascii
    $s15 = "host = \"51457\";" fullword ascii
    $s16 = "  forward = \"64\"," fullword ascii
    $s17 = "originalProperties[global + offsetParent]();" fullword ascii
    $s18 = "Code + orig + uniqueID);" fullword ascii
    $s19 = "while(fnOut[preventDefault + deepDataAndEvents + opener + wrap] < ((0 ^ parseJSON) | (2 * newUnmatched))) {" fullword ascii
    $s20 = "w = ((52 * rclickable + 49), (((rmouseEvent / 4) * newUnmatched + (1 * siblingCheck)), this));" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}