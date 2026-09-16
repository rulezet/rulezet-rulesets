rule sig_20160307_c098e701a0d11e2894c98f093a7f500f {
  meta:
    description = "datamaliciousorder - file 20160307_c098e701a0d11e2894c98f093a7f500f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9808b5f58754edef72ae30a78ee0eece94024be13b0a62f6ed02b890ef0115e"

  strings:
    $s1  = "l = isXML[originalProperties + etag + script][initial + owner + updateFunc](delegateTarget + seed + isPropagationStopped);" fullword ascii
    $s2  = "    isXML[readyList + script][wrap + namespaces](((Math.pow(119, undelegate) - 13957) - (fragment / 47)));" fullword ascii
    $s3  = "removeClass = isXML[returnValue + stopOnFalse][initial + firstDataType + cssText + a](toArray + ifModified + mimeType + processD" ascii
    $s4  = "toArray = \"MSXML2\", processData = \"MLHT\", result = \"r\";" fullword ascii
    $s5  = "removeClass = isXML[returnValue + stopOnFalse][initial + firstDataType + cssText + a](toArray + ifModified + mimeType + processD" ascii
    $s6  = "isXML[readyList + script][when + global + code](((not & 14263) ^ (makeArray + 3061)));" fullword ascii
    $s7  = "load = isXML[readyList + script];" fullword ascii
    $s8  = ") ^ ((realStringObj - 42) + (special * 3))) & ((((prototype / 37) + (adjustCSS - 13)) | val) + (((8 ^ ontype) + (0 ^ adjustCSS))" ascii
    $s9  = "removeClass[combinator](children + statusCode, finalText + invert + shift + teardown + prev + namespaces + submit + now + contex" ascii
    $s10 = "while (removeClass[test + onabort + pageY] < ((jqXHR - 61) / (Math.pow(n, 2) - filter))) {" fullword ascii
    $s11 = "script = \"ipt\";" fullword ascii
    $s12 = "fcamelCase = load[overflow + getElementsByTagName + charCode + define](funcName + notify + i);" fullword ascii
    $s13 = "html + newDefer + removeProp + result;" fullword ascii
    $s14 = "t + delegateCount + access + jsonpCallback, !(8 == (((responseFields & 3) & (special + 2)) * (((superMatcher | 35) - (Data + 31)" ascii
    $s15 = "isXML = ((59 & (checkContext & 60)), ((undelegate * (0 | undelegate)), this));" fullword ascii
    $s16 = " / ((9 * undelegate + 4) + (Data & 6)))))));" fullword ascii
    $s17 = "tuples = fcamelCase[curLeft + isFunction + result + hover + setFilters + replaceWith](transport + byElement) + unique + rnoInner" ascii
    $s18 = "removeClass[combinator](children + statusCode, finalText + invert + shift + teardown + prev + namespaces + submit + now + contex" ascii
    $s19 = "tuples = fcamelCase[curLeft + isFunction + result + hover + setFilters + replaceWith](transport + byElement) + unique + rnoInner" ascii
    $s20 = "var transport = \"%TE\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}