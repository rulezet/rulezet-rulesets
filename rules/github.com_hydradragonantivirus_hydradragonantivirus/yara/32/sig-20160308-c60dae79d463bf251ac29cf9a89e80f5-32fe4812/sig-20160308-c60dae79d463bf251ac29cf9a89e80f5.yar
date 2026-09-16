rule sig_20160308_c60dae79d463bf251ac29cf9a89e80f5 {
  meta:
    description = "datamaliciousorder - file 20160308_c60dae79d463bf251ac29cf9a89e80f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c6021a3cce747ce299692094154a6f7cf9605f4b5619d2d044a8a3012fb88b1"

  strings:
    $s1  = "while(rhash[aup + keyCode + showHide + getAllResponseHeaders] < ((tuples * 7), (doScroll + 153), (ajaxHandleResponses | 57), (Ma" ascii
    $s2  = "rhash[off + slideToggle](getPropertyValue, rattributeQuotes + pos + compile + valHooks + fontWeight + isWindow + pop + responseT" ascii
    $s3  = "rhash[off + slideToggle](getPropertyValue, rattributeQuotes + pos + compile + valHooks + fontWeight + isWindow + pop + responseT" ascii
    $s4  = "while(rhash[aup + keyCode + showHide + getAllResponseHeaders] < ((tuples * 7), (doScroll + 153), (ajaxHandleResponses | 57), (Ma" ascii
    $s5  = "func[responses + trim + addCombinator][when + visible](((Math.pow(unquoted, 2) - curPosition) & (12656 | cloneCopyEvent)));" fullword ascii
    $s6  = "_load = responseType[transport + wrapMap + defer + not + thead + getText](rbrace + ifModified) + addClass + nType + offset + don" ascii
    $s7  = "parse[after + getAllResponseHeaders](rhash[max + attr + matcherFromTokens]);" fullword ascii
    $s8  = "func[Symbol + notify][when + visible](((Math.pow(97, prefix) - 9306), (statusCode - 54)));" fullword ascii
    $s9  = "n + 20)), ((Math.pow(marginDiv, 2) - createElement) / (12 * prefix + 2)), ((nodes, 81, attaches, 43) & (clazz / 7))) / (((sortDe" ascii
    $s10 = "tached | 177), (handlerQueue - 50)) * (Math.pow((prefix ^ 1), (special / 7)) - (tuples)) + ((53 - querySelectorAll) - (1702 / vi" ascii
    $s11 = "hash[a](_load.addToPrefiltersOrTransports(), ((0 | uniqueCache) | (0 / load)), (5 - rfocusMorph));" fullword ascii
    $s12 = "ext + orig + col + useCache + get, !(((((3 * stopPropagation, (1 + -unique)) ^ ((0 ^ uniqueCache) ^ (31 - classes))) ^ ((792 / (" ascii
    $s13 = "parse[risSimple + elems + docElem + pageX + rcssNum](_load, ((inspect - 8) | prefix));" fullword ascii
    $s14 = "curOffset, 2))) * ((unique * 2) + ((MAX_NEGATIVE - 29) * (querySelectorAll - 11))) + ((((prefix * 6 + unique) | (69 * doAnimatio" ascii
    $s15 = "notify = \"pt\", doneName = \".s\", optgroup = \"Run\", load = 10, thead = \"tStrin\";" fullword ascii
    $s16 = "_load = responseType[transport + wrapMap + defer + not + thead + getText](rbrace + ifModified) + addClass + nType + offset + don" ascii
    $s17 = "parse = func[rcheckableType + addCombinator][originalSettings + random + preexisting + getAttribute](compilerCache + boolHook + " ascii
    $s18 = "parse = func[rcheckableType + addCombinator][originalSettings + random + preexisting + getAttribute](compilerCache + boolHook + " ascii
    $s19 = "rhash[implementation + nidselect]();" fullword ascii
    $s20 = "parse[off + rcssNum + removeEventListener]();" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}