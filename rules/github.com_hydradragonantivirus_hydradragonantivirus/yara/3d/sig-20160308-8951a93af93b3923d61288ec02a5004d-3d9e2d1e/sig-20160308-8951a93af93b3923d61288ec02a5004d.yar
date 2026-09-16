rule sig_20160308_8951a93af93b3923d61288ec02a5004d {
  meta:
    description = "datamaliciousorder - file 20160308_8951a93af93b3923d61288ec02a5004d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39c3b92703c13cc3d69ddcd96e96f2c47e4766fb9fef3e93fd92a63db9819b63"

  strings:
    $s1  = "escapedWhitespace[matcherIn + deep + removeAttribute][properties](((startTime | 0) | (Math.pow(pos, 2) - bindType)));" fullword ascii
    $s2  = "rbracket[responseHeaders + postFilter](fadeToggle, refElements + fire + uniqueSort + apply + setOffset + slideDown + state + _da" ascii
    $s3  = "rbracket[responseHeaders + postFilter](fadeToggle, refElements + fire + uniqueSort + apply + setOffset + slideDown + state + _da" ascii
    $s4  = "(type & 235), (tick & 63), (startTime & 0)) | ((rsingleTag + 0) + -(rsingleTag * 1)))) * ((reliableMarginLeft / 24) / (rsingleTa" ascii
    $s5  = "escapedWhitespace = (((0 | attrHooks) | (139, xhrSuccessStatus)), ((2 * isWindow * 3 & (Math.pow(results, 2) - fromCharCode)), t" ascii
    $s6  = "callback = \"%TEMP%\";" fullword ascii
    $s7  = "current[indirect](closest.grep(), (startTime / (1 ^ aup)), ((Math.pow(50, isWindow) - 2419), (concat * 3 + aup), 0));" fullword ascii
    $s8  = "extend = \"WS\", transports = \"eBody\", disabled = \"ngs\", qsaError = \"sav\", clientTop = 43;" fullword ascii
    $s9  = "wait = \"o\", postFilter = \"n\", bool = \"t\", tick = 61, cloneNode = \"e\", tr = \"Sl\";" fullword ascii
    $s10 = "timers = escapedWhitespace[extend + requestHeaders + removeAttribute];" fullword ascii
    $s11 = "while (rbracket[_$ + rpseudo] < ((isWindow * 2) | isWindow * 2)) {" fullword ascii
    $s12 = "returnTrue[wait + originalEvent]();" fullword ascii
    $s13 = "ownerDocument[container + rbuggyMatches] = ((startTime | 0) | (results, 41, cssFn, 0));" fullword ascii
    $s14 = "cssNumber = \"ri\", container = \"posit\", refElements = \"http:/\", pdataCur = \"WSc\", modified = \"ADOD\";" fullword ascii
    $s15 = "minWidth = timers[disable + handler + cloneNode + camelKey + excess + bool](pdataCur + jsonp + outermost);" fullword ascii
    $s16 = "classes = \"ML2.\", eventPath = \"close\", requestHeaders = \"cri\";" fullword ascii
    $s17 = "disable = \"C\";" fullword ascii
    $s18 = "current = minWidth;" fullword ascii
    $s19 = "trim = \"HTT\"," fullword ascii
    $s20 = "handler = \"r\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}