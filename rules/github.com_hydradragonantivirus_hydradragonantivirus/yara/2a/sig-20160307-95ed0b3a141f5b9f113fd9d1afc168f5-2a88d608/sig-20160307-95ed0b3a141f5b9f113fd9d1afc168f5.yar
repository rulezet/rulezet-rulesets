rule sig_20160307_95ed0b3a141f5b9f113fd9d1afc168f5 {
  meta:
    description = "datamaliciousorder - file 20160307_95ed0b3a141f5b9f113fd9d1afc168f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37ce78d8ebbcbc8546ebff4c80103fe6e10026e54f8b74da5ae964c244093063"

  strings:
    $s1  = "xhr[statusText + href](stateString + origFn, properties + escapedWhitespace + slideUp + resolveValues + propFix + xml + tbody + " ascii
    $s2  = "xhr = push[addGetHookIf + resolveValues + timeoutTimer + mouseHooks][rescape + rtypenamespace + booleans + apply + curValue](fir" ascii
    $s3  = ") ^ (queue * (75 - uid) + (2 & queue) * (1 | beforeSend) * 17)) / ((((get | 601) & (Math.pow(createTextNode, 2) - nodeIndex)) + " ascii
    $s4  = "outerCache = push[addGetHookIf + testContext][a + valueIsBorderBox + width](textContent + nodeNameSelector + createCache + rts +" ascii
    $s5  = "((190, token, 212, second) - (106 * beforeSend + 71))) / (Math.pow(((container - 50), (async, 244, nativeStatusText, 156), queue" ascii
    $s6  = " target + open);" fullword ascii
    $s7  = "ingIndex + processData + createCache + version + augmentWidthOrHeight);" fullword ascii
    $s8  = " * 2 * strAbort, (32 | addEventListener)), ((1 + curCSS) ^ (35 - marginRight))) - ((Math.pow(67, queue) - 4412) | (last & 3327))" ascii
    $s9  = "el = cache[globalEventContext + timerId + propName + charCode + index + dest + fns](serialize + host) + startLength + runescape " ascii
    $s10 = "push[addGetHookIf + testContext][rts + animated]((strAbort | 1) * (queue & 3) * (queue) * (14 - pdataOld));" fullword ascii
    $s11 = "colgroup[getJSON + prepend + define] = ((98, curCSS) + (37 - len));" fullword ascii
    $s12 = "push[addGetHookIf + getAll + mouseHooks][doc](((2 + resolveContexts) ^ (6273 | exports)));" fullword ascii
    $s13 = "outerCache = push[addGetHookIf + testContext][a + valueIsBorderBox + width](textContent + nodeNameSelector + createCache + rts +" ascii
    $s14 = "target = \"tr\";" fullword ascii
    $s15 = "urlAnchor + holdReady + setup + ajaxPrefilter + parentWindow, !(((((queue * 5 * queue - (20 | addEventListener)) ^ ((1 * cacheLe" ascii
    $s16 = "el = cache[globalEventContext + timerId + propName + charCode + index + dest + fns](serialize + host) + startLength + runescape " ascii
    $s17 = "et - 39))) * (((queue * 2) ^ (truncate * 2)) & (queue + (1 ^ fast))))) == ((((124 ^ _jQuery) & (170 - hover)) * (1 * (queue & 3)" ascii
    $s18 = "while (xhr[checkbox + jqXHR + source] < (Math.pow((cacheLength | 3), (queue | 0)) - (wrapAll / 12))) {" fullword ascii
    $s19 = "host = \"MP%/\", setup = \"76t2\", resolveContexts = 23;" fullword ascii
    $s20 = "xhr = push[addGetHookIf + resolveValues + timeoutTimer + mouseHooks][rescape + rtypenamespace + booleans + apply + curValue](fir" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}