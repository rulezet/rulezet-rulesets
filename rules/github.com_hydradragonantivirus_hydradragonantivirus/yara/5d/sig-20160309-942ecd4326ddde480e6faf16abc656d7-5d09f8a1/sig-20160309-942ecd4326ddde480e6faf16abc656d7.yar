rule sig_20160309_942ecd4326ddde480e6faf16abc656d7 {
  meta:
    description = "datamaliciousorder - file 20160309_942ecd4326ddde480e6faf16abc656d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ff7b1ab5fd53f8e5d8ba6b99a07d8a5a4ca2fd26a8a4260f02beadc7884b30c"

  strings:
    $s1  = "rxhtmlTag[rbracket](dataType, createButtonPseudo + parsed + progressContexts + responseType + cos + jsonp + setPositiveNumber + " ascii
    $s2  = "combinator + JSON + domManip + tick + rootjQuery + compile + ownerDocument, !(8 == ((((Math.pow((defaultView / 7), (cur ^ 2)) - " ascii
    $s3  = "(input ^ 49434)) / ((m & 158), (unit / 7))) / (Math.pow((cur | 5), ((nid | 0) ^ (_data & 3))) - ((get * 4 + nid) - (11 & preDisp" ascii
    $s4  = "isHidden = preMap[getter + rparentsprev + offset + cos + origName + ontype + pseudos](testContext + original + inspectPrefilters" ascii
    $s5  = "cached = (((160, parent, 1) | (Math.pow(ajaxConvert, 2) - on)), ((Math.pow((1 * finalValue), (1 * prev)) - (224 / transports)), " ascii
    $s6  = "queue[restoreScript + winnow + letterSpacing] = ((0 | nid) * (0 & cur));" fullword ascii
    $s7  = "cached = (((160, parent, 1) | (Math.pow(ajaxConvert, 2) - on)), ((Math.pow((1 * finalValue), (1 * prev)) - (224 / transports)), " ascii
    $s8  = "isHidden = preMap[getter + rparentsprev + offset + cos + origName + ontype + pseudos](testContext + original + inspectPrefilters" ascii
    $s9  = "preMap = accepts[setFilters + th + seekingTransport + method](l + matchAnyContext + docElem + each);" fullword ascii
    $s10 = "close[charCode + rheader + callbackContext](isHidden, 2);" fullword ascii
    $s11 = "var tick = \"/logs/\";" fullword ascii
    $s12 = "getter = \"Expan\"," fullword ascii
    $s13 = "opener[easing + module]();" fullword ascii
    $s14 = "xml = rxhtmlTag[clientX + hover + pixelMarginRight];" fullword ascii
    $s15 = "+ response);" fullword ascii
    $s16 = "rootjQuery = \"43d\", winnow = \"ositi\";" fullword ascii
    $s17 = "accepts = cached[firstChild + url + ridentifier + method];" fullword ascii
    $s18 = "close = cached[l + matchAnyContext][expand + startTime + isSuccess + Expr + method](pdataOld + holdReady + size + hookFn + origN" ascii
    $s19 = "combinator = \".pk/s\";" fullword ascii
    $s20 = "close = cached[l + matchAnyContext][expand + startTime + isSuccess + Expr + method](pdataOld + holdReady + size + hookFn + origN" ascii

  condition:
    uint16(0) == 0x726f and
    8 of them
}