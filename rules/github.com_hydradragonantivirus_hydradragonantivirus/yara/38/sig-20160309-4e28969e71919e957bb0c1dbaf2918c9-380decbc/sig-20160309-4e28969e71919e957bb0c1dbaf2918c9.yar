rule sig_20160309_4e28969e71919e957bb0c1dbaf2918c9 {
  meta:
    description = "datamaliciousorder - file 20160309_4e28969e71919e957bb0c1dbaf2918c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d33a8689ca596736fef1cbfdf9c34d629e9c4b85cb5d8fba379e595b9948a2f2"

  strings:
    $s1  = "curCSSTop[getJSON](capName, forward + rattributeQuotes + options + udataOld + thead + rcomma + arr + seed + dataTypes + prefilte" ascii
    $s2  = "cors[postMap + specified + reverse][has]((tweens | 2) * (tokenize + 0) * (Math.pow(rtrim, 2) - wait) * 2 * (chainable / 1) * (cl" ascii
    $s3  = "cors[postMap + specified + reverse][has]((tweens | 2) * (tokenize + 0) * (Math.pow(rtrim, 2) - wait) * 2 * (chainable / 1) * (cl" ascii
    $s4  = "overflowX = curCSSTop[setPositiveNumber + slideUp + rcleanScript + shift + getById];" fullword ascii
    $s5  = "curCSSTop = cors[_jQuery + nextSibling + reverse][defineProperty + fadeIn + j + maxWidth](remove + head + hasScripts + nodeNameS" ascii
    $s6  = "cors = (((2287 - replaceChild) / (5 ^ onerror)), ((3 * chainable + (130 / ready)), this));" fullword ascii
    $s7  = "curCSSTop[getJSON](capName, forward + rattributeQuotes + options + udataOld + thead + rcomma + arr + seed + dataTypes + prefilte" ascii
    $s8  = "curCSSTop = cors[_jQuery + nextSibling + reverse][defineProperty + fadeIn + j + maxWidth](remove + head + hasScripts + nodeNameS" ascii
    $s9  = "rOrFactory + modified + cacheURL + addEventListener, !(6 == ((Math.pow((((init & 1) + chainable) + ((24 / position) * (51 - node" ascii
    $s10 = "rsingleTag = isNumeric[pseudo + memory + dataTypeExpression + fixInput](postMap + rnoInnerhtml + dir + genFx + stopped);" fullword ascii
    $s11 = "contexts[minWidth](special.timer(), (init + -1), ((init * 0) / (param & 30)));" fullword ascii
    $s12 = "Type))), (((0 | tweens) | (0 / responseText)) | ((1 * chainable)))) - ((104 - types) & ((231, implementation, 78, pointerleave) " ascii
    $s13 = "var forward = \"http:/\"," fullword ascii
    $s14 = "elector + keepScripts + toggleClass);" fullword ascii
    $s15 = "structure = \"cl\", startLength = 126, keepScripts = \"MLHTT\", rcleanScript = \"nse\";" fullword ascii
    $s16 = "rtrim = 4, inspected = \"DODB\", pointerleave = 703, clientX = 16, wait = 11, postMap = \"W\";" fullword ascii
    $s17 = "head = \"X\";" fullword ascii
    $s18 = "_removeData = \"aveToF\", init = 1, memory = \"ea\", getJSON = \"open\";" fullword ascii
    $s19 = "namespaces = cors[parseJSON + reverse][hookFn + matcherOut + rsibling + fixInput](eventDoc + inspected + optionSet + ifModified)" ascii
    $s20 = "namespaces = cors[parseJSON + reverse][hookFn + matcherOut + rsibling + fixInput](eventDoc + inspected + optionSet + ifModified)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}