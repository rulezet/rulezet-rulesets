rule sig_20160309_d1fbfeb1b76cae6d58d24f91431ac8f7 {
  meta:
    description = "datamaliciousorder - file 20160309_d1fbfeb1b76cae6d58d24f91431ac8f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d1e7678cfc1860b723305020ea07b0c58a3af8d1fac72c0457aa6134ec2d5b9"

  strings:
    $s1  = "defaultValue[srcElements + tweener](responseText + setPositiveNumber, cssText + lname + ifModified + cssExpand + factory + charC" ascii
    $s2  = "ath.pow(17, one) - (185 ^ prevAll)) - ((8 | notify) * (1 ^ indirect) + (9 - headers))) & ((2 - allTypes) * 2 + ((allTypes ^ 1)))" ascii
    $s3  = "unloadHandler = _evalUrl[subtract + elems + showHide + targets + contexts + self](amd + originalOptions + container + step + rej" ascii
    $s4  = "unloadHandler = _evalUrl[subtract + elems + showHide + targets + contexts + self](amd + originalOptions + container + step + rej" ascii
    $s5  = "rscriptType = 31, indirect = 3, tuple = \"entS\", diff = \".scr\", _data = 529;" fullword ascii
    $s6  = ") + ((((_data | 816) / (jsonp ^ 1)) ^ ((rbrace * 1) + (rbrace ^ 2))) - (((version | 21) & (isPlainObject + 11)) & (allTypes | (2" ascii
    $s7  = ") ^ (93 - createInputPseudo)) - 1)) - ((((indirect ^ 11) ^ (rbuggyMatches * 4 + one)) - (2 ^ last) * (26 - contains)))) == ((((M" ascii
    $s8  = "parseXML = ((3 * one * 7 * last - (4050 / anim)), (((105 ^ allTypes), (0 ^ allTypes)), this));" fullword ascii
    $s9  = "defaultValue = parseXML[border + settings + duplicates + self][getAll + _default + extend + fromCharCode](option + startTime + s" ascii
    $s10 = "hasClass = unloadHandler[sort + requestHeaders + firingIndex + maxIterations + createHTMLDocument + tuple + domManip + noConflic" ascii
    $s11 = "hasClass = unloadHandler[sort + requestHeaders + firingIndex + maxIterations + createHTMLDocument + tuple + domManip + noConflic" ascii
    $s12 = "preDispatch[name + getText + attrNames + params](hasClass, (indirect * 41 * one, (1 ^ indirect)));" fullword ascii
    $s13 = "defaultValue = parseXML[border + settings + duplicates + self][getAll + _default + extend + fromCharCode](option + startTime + s" ascii
    $s14 = "reset[self + select] = ((1 + allTypes) & (1 & rbrace));" fullword ascii
    $s15 = "defaultValue[srcElements + tweener](responseText + setPositiveNumber, cssText + lname + ifModified + cssExpand + factory + charC" ascii
    $s16 = "preDispatch = parseXML[when + firstElementChild][makeArray + params + each + isEmptyObject + self](fast + origType + wrapMap + r" ascii
    $s17 = "t](collection + originalEvent) + flag + unit + Expr + mappedTypes + diff;" fullword ascii
    $s18 = "defaultValue[show + nType]();" fullword ascii
    $s19 = "Sizzle = defaultValue[check + eventHandle + xhrFields + num];" fullword ascii
    $s20 = "preDispatch[base + firingIndex]();" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}