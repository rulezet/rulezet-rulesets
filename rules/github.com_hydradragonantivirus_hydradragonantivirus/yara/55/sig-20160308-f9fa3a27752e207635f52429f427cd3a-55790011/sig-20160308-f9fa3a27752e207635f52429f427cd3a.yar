rule sig_20160308_f9fa3a27752e207635f52429f427cd3a {
  meta:
    description = "datamaliciousorder - file 20160308_f9fa3a27752e207635f52429f427cd3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14669b2db2080a6388e7efcd204151451780d11e0833ebb8c4ef8d4d3aba4c28"

  strings:
    $s1  = "isPlainObject = postFinder[cloneNode + isSuccess + password + attaches][close + rtypenamespace + bup + display](dataPriv + updat" ascii
    $s2  = "tById + module, !((((((105 - unbind), (5 * responseHeadersString + 2), (ajaxSettings * 5 + idx), (2 & createFxNow)) * ((231 ^ de" ascii
    $s3  = "postFinder = (((187 ^ onlyHandlers) - (11 + cssShow)), (((9 & tmp) + (64, _evalUrl)), this));" fullword ascii
    $s4  = "isPlainObject = postFinder[cloneNode + isSuccess + password + attaches][close + rtypenamespace + bup + display](dataPriv + updat" ascii
    $s5  = "isPlainObject[getText](stopPropagation, overflow + fn + toggleClass + rheaders + handlerQueue + acceptData + context + getElemen" ascii
    $s6  = "postFinder[status + unshift + addBack][rcombinators + tuples](((62, pageXOffset, 30) + createHTMLDocument * 5 * expand));" fullword ascii
    $s7  = "statusCode = postFinder[status + tbody + attaches][rtagName + compare + ofType + addHandle](getAllResponseHeaders + slideToggle " ascii
    $s8  = "statusCode = postFinder[status + tbody + attaches][rtagName + compare + ofType + addHandle](getAllResponseHeaders + slideToggle " ascii
    $s9  = "legateType) / (0 | delegate)) + ((11 + _$) / (Math.pow(26, createHTMLDocument) - 642))) - (((newSelector / 1) & (Math.pow(stop, " ascii
    $s10 = "2) - matched)) | ((Math.pow(22, createHTMLDocument) - 444)))) + (((Math.pow(notifyWith, 2) - input) / (9 ^ defer)) & 0)) == matc" ascii
    $s11 = "complete[firstElementChild](getClass.dirruns(), (87, camelKey, 148, keyCode), 0);" fullword ascii
    $s12 = "var password = \"rip\"," fullword ascii
    $s13 = "getClass = find[includeWidth + protocol + isFunction + preferredDoc + markFunction + isNumeric + fadeToggle](errorCallback + dom" ascii
    $s14 = "getClass = find[includeWidth + protocol + isFunction + preferredDoc + markFunction + isNumeric + fadeToggle](errorCallback + dom" ascii
    $s15 = "isSuccess = \"c\", simple = \".s\", compare = \"eat\", stopPropagation = \"GET\", acceptData = \"ko\", isTrigger = \"ll\";" fullword ascii
    $s16 = "implementation[cssNumber] = ((1 + keyCode) + (1 & keyCode));" fullword ascii
    $s17 = "root = \"HTTP\"," fullword ascii
    $s18 = "isPlainObject[getText](stopPropagation, overflow + fn + toggleClass + rheaders + handlerQueue + acceptData + context + getElemen" ascii
    $s19 = "statusCode[pseudo + nextSibling](isPlainObject[setMatched + responseType + handleObj + outermost]);" fullword ascii
    $s20 = "statusCode[adjustCSS + active]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}