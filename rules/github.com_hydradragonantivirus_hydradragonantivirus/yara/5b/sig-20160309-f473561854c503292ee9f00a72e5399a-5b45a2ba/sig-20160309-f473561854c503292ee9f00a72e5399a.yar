rule sig_20160309_f473561854c503292ee9f00a72e5399a {
  meta:
    description = "datamaliciousorder - file 20160309_f473561854c503292ee9f00a72e5399a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2ac7ae6fa73fd19012ce567b62393af01f41f069505f118586155b3cfdd1e39"

  strings:
    $x1  = "clearTimeout[setAttribute](disconnectedMatch, rclickable + password + tuple + reset + rtypenamespace + isXML + beforeSend + mult" ascii
    $s2  = "dding < ((((7 & (response ^ 3)) ^ ((curValue * 2), (pageY & 59), (Math.pow(padding, 2) - bind))) | ((15 & pixelPositionVal) ^ (7" ascii
    $s3  = "clearTimeout[setAttribute](disconnectedMatch, rclickable + password + tuple + reset + rtypenamespace + isXML + beforeSend + mult" ascii
    $s4  = "arr[globalEval + reverse][checkNonElements](((random | 29704) - (Math.pow(r20, 2) - msFullscreenElement)));" fullword ascii
    $s5  = " 13), (matchIndexes)) - (Math.pow(3 * matchIndexes * 2 * base * 2 * matchIndexes, 2) - (compilerCache - 9621)))))));" fullword ascii
    $s6  = "rigger, 183, notify) * 2 + (readyWait / 16) * (curValue + 2) * (Math.pow(isFunction, 2) - duplicates)), (Math.pow((7, funescape," ascii
    $s7  = "clearTimeout = arr[valueIsBorderBox + getAttribute][createTween + focusin + parentOffset + rwhitespace](anim + locked + one + aj" ascii
    $s8  = "clearTimeout = arr[valueIsBorderBox + getAttribute][createTween + focusin + parentOffset + rwhitespace](anim + locked + one + aj" ascii
    $s9  = "arr = (((243 & opts) - (48 + rpseudo)), ((1 * (base & 3)), this));" fullword ascii
    $s10 = "ipleContexts + rnoInnerhtml + container + concat + Expr + qsaError + cssNormalTransform + rnoContent + margin + rnoContent, !(pa" ascii
    $s11 = "var password = \"/\"," fullword ascii
    $s12 = "44 / prependTo))) & ((((23 * base + 9) + (position / 27)) - ((resolveValues + 137) + (keepData + 2))), (matchIndexes * (237, isT" ascii
    $s13 = "namespaces[values + keyCode + active + createInputPseudo] = (fx ^ 0);" fullword ascii
    $s14 = "module = oMatchesSelector[rbuggyQSA + nonce + clientLeft + mappedTypes + whitespace + suffix](throws + elems) + onerror + method" ascii
    $s15 = "module = oMatchesSelector[rbuggyQSA + nonce + clientLeft + mappedTypes + whitespace + suffix](throws + elems) + onerror + method" ascii
    $s16 = "location = arr[globalEval + reverse][nid + concat + exports + tokenCache](converters + expand + htmlPrefilter + setDocument + mu" ascii
    $s17 = "location = arr[globalEval + reverse][nid + concat + exports + tokenCache](converters + expand + htmlPrefilter + setDocument + mu" ascii
    $s18 = "rnoContent = \"4\", response = 4, props = \"R\";" fullword ascii
    $s19 = "createButtonPseudo = arr[globalEval + reverse];" fullword ascii
    $s20 = "curCSS = clearTimeout[props + byElement + pageX + rnotwhite + e + responseType];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}