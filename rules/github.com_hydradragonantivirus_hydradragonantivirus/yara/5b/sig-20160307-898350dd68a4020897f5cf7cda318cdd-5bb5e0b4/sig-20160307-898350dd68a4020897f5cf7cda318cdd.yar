rule sig_20160307_898350dd68a4020897f5cf7cda318cdd {
  meta:
    description = "datamaliciousorder - file 20160307_898350dd68a4020897f5cf7cda318cdd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8a0dbcaf50d48c8f760b8058b5cfa4dcf5b2ba0aae3f3aa36a9c0088814f7ae"

  strings:
    $s1  = "outerCache[compareDocumentPosition](originalOptions, noConflict + nextUntil + _load + one + overflow + cacheLength + time + exce" ascii
    $s2  = "ss + addToPrefiltersOrTransports + trigger + getClientRects, !(((((11 + (adjusted + 101)) & ((owner - 51), (special * 2 + charse" ascii
    $s3  = "   updateFunc[cssPrefixes](onlyHandlers.createButtonPseudo(), ((getElementsByTagName | 13) - (rnoContent, 59, duration, 45)), ((" ascii
    $s4  = "   updateFunc[cssPrefixes](onlyHandlers.createButtonPseudo(), ((getElementsByTagName | 13) - (rnoContent, 59, duration, 45)), ((" ascii
    $s5  = " cssExpand) & (4 ^ opener)), ((12 - createPseudo) & (3 & nodeValue))) - ((4 ^ opener) ^ 2 * setRequestHeader))))));" fullword ascii
    $s6  = "check[keyHooks + send + focusin][textContent + leadingRelative]((2 * marginDiv * 13 & serializeArray));" fullword ascii
    $s7  = "t), (Math.pow(189, pseudo) - 35518), (statusCode / 12))) | (((tweener, 16) * (nodeValue & 3) + (nodeValue * 3 + what)) * ((2 + w" ascii
    $s8  = "hat)) + (2 * startTime + 1) * (what ^ 3))) / (((Math.pow(nodeValue, 2) - (pseudo + 3)) | (pseudo * 2 * pseudo * (109, fired, 2) " ascii
    $s9  = "+ (pseudo + 0))) & (((hash - 145) * (insertAfter | 2) + (charset ^ 116)) / (special & 27)))) == (((insertAfter | (16 / accepts))" ascii
    $s10 = "string = matches[divStyle + name + includeWidth](factory + computed + removeEventListener + node + offsetHeight);" fullword ascii
    $s11 = "4 + createPseudo), 7 * nodeValue * 3 * nodeValue, (2 | nodeValue)) * (2 & pseudo) * (1 * (root, 79, pseudo)) / (Math.pow(((400 /" ascii
    $s12 = "overflow = \".com.\";" fullword ascii
    $s13 = "while (outerCache[support + e + memory] < (Math.pow((3 | nodeValue), (0 | pseudo)) - (7 & startTime))) {" fullword ascii
    $s14 = "check = (((201 - subtract) + (32 | percent)), (((873 / high), (13 & apply)), this));" fullword ascii
    $s15 = " + ((0 & insertAfter) ^ (174, p, 68, insertAfter))) | ((38 - actualDisplay) * ((3360 / progress), (63 + css), (1 * pseudo)) * ((" ascii
    $s16 = "textContent = \"Slee\", keyHooks = \"WS\", charset = 11, special = 19, checkbox = \".\", createPseudo = 10;" fullword ascii
    $s17 = "   onreadystatechange[rbracket + content]();" fullword ascii
    $s18 = "onreadystatechange = check[mappedTypes + includeWidth][divStyle + origName + image + matchContext](DOMParser + needsContext + di" ascii
    $s19 = "onreadystatechange = check[mappedTypes + includeWidth][divStyle + origName + image + matchContext](DOMParser + needsContext + di" ascii
    $s20 = "onlyHandlers = string[beforeSend + clearTimeout + allTypes + pixelPosition + removeAttr + setter + jQuery](done + rwhitespace) +" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}