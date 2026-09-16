rule sig_20160308_97d41c1f71bc2c82777bc79d7411441c {
  meta:
    description = "datamaliciousorder - file 20160308_97d41c1f71bc2c82777bc79d7411441c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adc2fb6f43940c67c623201bc39535679da33e4bd7a50211b9608b7ca9d98b49"

  strings:
    $s1  = "while (_$[timer + targets + isBorderBox + addGetHookIf + transport] < (rcleanScript * 3 * rcleanScript / (69 / elemLang))) {" fullword ascii
    $s2  = "_$[list + getElementsByName](document + isArray, matchedCount + conv + conv + eventPath + etag + createPositionalPseudo + round " ascii
    $s3  = "getPropertyValue = \"%TEMP%\";" fullword ascii
    $s4  = "dispatch[letter + noGlobal + andSelf][emptyGet](((16192 & responseHeadersString) ^ 191 * rcleanScript * 2 * rcleanScript * 5));" fullword ascii
    $s5  = "dispatch[disableScript + handlerQueue + andSelf][emptyGet](((21 | async) * (3 | newContext) + (13 | tuples)));" fullword ascii
    $s6  = "matchedCount = \"http:\", getAttributeNode = \"egim\", types = \"teQuot\", newContext = 1, boolHook = 49, simple = \"i.jp\";" fullword ascii
    $s7  = "_$ = dispatch[getAllResponseHeaders + _data + fire][firingIndex + timeStamp + body + fire](getText + b + compare + b + noop + is" ascii
    $s8  = "_$ = dispatch[getAllResponseHeaders + _data + fire][firingIndex + timeStamp + body + fire](getText + b + compare + b + noop + is" ascii
    $s9  = "+ getAttributeNode + simple + cssPrefixes, !(10 < (((tuples * (17, location, 5) * (compareDocumentPosition - 12) * (apply ^ 13) " ascii
    $s10 = "progress = setAttribute[hover + now + opt + open + when + getElementsByName + tokenize + simulate](getPropertyValue + conv) + ca" ascii
    $s11 = "dispatch = ((5 | tuples) * (54 - boolHook) * (3 ^ multipleContexts), (((6 * rcleanScript + 1) - (removeClass)), this));" fullword ascii
    $s12 = "returned = dispatch[disableScript + sortInput + fire][has + handler + hookFn](push + sibling + fx + documentIsHTML);" fullword ascii
    $s13 = " count)))) / ((((1 | newContext) & (1 * newContext)) * ((4 + rcleanScript) & (1 * tuples))) ^ (((1 * newContext) * (612 / MAX_NE" ascii
    $s14 = "returned[writable + seekingTransport + clearInterval](_$[identifier + createButtonPseudo + wrapInner]);" fullword ascii
    $s15 = "_$[list + getElementsByName](document + isArray, matchedCount + conv + conv + eventPath + etag + createPositionalPseudo + round " ascii
    $s16 = "GATIVE)) - (7 & (count - 24)))))));" fullword ascii
    $s17 = "apply = 16, conv = \"/\", getElementsByName = \"n\", token = \"eateOb\", orig = \"ipt\";" fullword ascii
    $s18 = "progress = setAttribute[hover + now + opt + open + when + getElementsByName + tokenize + simulate](getPropertyValue + conv) + ca" ascii
    $s19 = "melKey + setFilters + types + timeout + mimeType + unit;" fullword ascii
    $s20 = "setAttribute = optionSet[has + token + rfocusMorph](newCache + rootjQuery + pdataCur + curCSSLeft);" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}