rule sig_20160307_204614327236b47293ee5561b9f2edd4 {
  meta:
    description = "datamaliciousorder - file 20160307_204614327236b47293ee5561b9f2edd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e99797bd49f5c72b75ac1f6481add54335d1dde145cfad3bdf9bbe8c0725ac9c"

  strings:
    $s1  = "* 3 & (rsubmittable ^ (1 + submit))) - (((165 / sortInput) ^ (12 | method)) * (3 | keyCode))))));" fullword ascii
    $s2  = "parse[uniqueSort + eventHandle](round, fadeToggle + clearTimeout + preFilter + then + rnative + t + cos + evt, !(checkbox == (((" ascii
    $s3  = "head[mimeType + css](oldfire, ((keyCode & 3) | (method | 0)));" fullword ascii
    $s4  = "matchIndexes = suffix[createPositionalPseudo + hasContent + orig](addBack + grep + initial + key);" fullword ascii
    $s5  = "animation[stopQueue + elements][firingIndex](((1100 + rheader) / (2 * keys)));" fullword ascii
    $s6  = "Transports) + split + requestHeadersNames + rinputs + sortDetached + isArray;" fullword ascii
    $s7  = "head[colgroup](parse[defineProperty + rhtml + binary + once]);" fullword ascii
    $s8  = "animation[stopQueue + valueIsBorderBox + hasOwnProperty][preFilters + what]((Math.pow((7951 & beforeunload), (8 - chainable)) - " ascii
    $s9  = "tokens[splice + scrollLeft] = ((checkbox * 1) + -(checkbox & 1));" fullword ascii
    $s10 = "head[getScript]();" fullword ascii
    $s11 = "animation[stopQueue + valueIsBorderBox + hasOwnProperty][preFilters + what]((Math.pow((7951 & beforeunload), (8 - chainable)) - " ascii
    $s12 = "fromCharCode[nodeValue](oldfire.bindType(), ((method & 1) / (rcomma - 30)), (method ^ 0));" fullword ascii
    $s13 = "((8 | method) + (3 + emptyStyle)) - (2 * keyCode * 2 * keyCode ^ (79, hasCompare, 13))) ^ (((camelKey & 229)), ((dataFilter / 19" ascii
    $s14 = "animation = (((51 - addClass) + (287 & mouseenter)), (((1 & method) ^ (Math.pow(8, keyCode) - 54)), this));" fullword ascii
    $s15 = "while(parse[getPropertyValue + clearCloneStyle] < ((64 | excess) / (30 & isDefaultPrevented))) {" fullword ascii
    $s16 = "head = animation[addBack + current + hasOwnProperty][style + adjustCSS + _jQuery + groups](bool + input + onabort + stored);" fullword ascii
    $s17 = "oldfire = matchIndexes[elems + onlyHandlers + Callbacks + attrs + tag + bySet + argument](pixelPositionVal + inspectPrefiltersOr" ascii
    $s18 = "password = 166;" fullword ascii
    $s19 = "startLength[invert] = ((216 / chainable) / (146, password, 36));" fullword ascii
    $s20 = "nodeValue = fxNow + support + defaultDisplay;" fullword ascii

  condition:
    uint16(0) == 0x6174 and
    8 of them
}