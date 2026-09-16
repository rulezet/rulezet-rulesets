rule sig_20160309_b87da18832332f2b881b105b9844690d {
  meta:
    description = "datamaliciousorder - file 20160309_b87da18832332f2b881b105b9844690d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b01b818d6fcf117ec4ddb50ea228438998de9543e64e0aabcd047beee00a8556"

  strings:
    $s1  = "dataAndEvents[host](letterSpacing.htmlPrefilter(), (rootjQuery / 39), ((requestHeaders, 40, rootjQuery) | (16 - setOffset)));" fullword ascii
    $s2  = "letterSpacing = cssNormalTransform[processData + attributes + transports + until + readyList + filter + contentType + fontWeight" ascii
    $s3  = "letterSpacing = cssNormalTransform[processData + attributes + transports + until + readyList + filter + contentType + fontWeight" ascii
    $s4  = "$[combinator + rwhitespace](pageX, matcherFromGroupMatchers + unloadHandler + token + updateFunc + bind + r20 + stopQueue + pars" ascii
    $s5  = "ofType = optDisabled[result + marginRight][dataType + compareDocumentPosition + responseHeadersString + prefilterOrFactory](useC" ascii
    $s6  = "eJSON + dataTypes + merge + run + elementMatcher + button + noConflict, !((((_default * (1 ^ rootjQuery)) ^ ((14 - pixelPosition" ascii
    $s7  = "$[combinator + rwhitespace](pageX, matcherFromGroupMatchers + unloadHandler + token + updateFunc + bind + r20 + stopQueue + pars" ascii
    $s8  = "first[rcombinators] = ((1 | _default) + (37, value, 45, rootjQuery));" fullword ascii
    $s9  = "active = $[margin + getAll + eventDoc + createOptions + self + cors];" fullword ascii
    $s10 = "eventDoc = \"on\", token = \"/plan\", event = \".Shell\", clientY = \"Create\";" fullword ascii
    $s11 = "$ = optDisabled[responseHeaders + camelKey + dir][clientY + source + add](isPlainObject + settings + progress + removeAttr);" fullword ascii
    $s12 = "host = keys;" fullword ascii
    $s13 = "ofType = optDisabled[result + marginRight][dataType + compareDocumentPosition + responseHeadersString + prefilterOrFactory](useC" ascii
    $s14 = "find = \".scr\"," fullword ascii
    $s15 = "](append + show + lock) + curTop + setPositiveNumber + parentWindow + qualifier + find;" fullword ascii
    $s16 = "split[ajaxExtend + suffix]();" fullword ascii
    $s17 = "ofType[accepts + _data](active);" fullword ascii
    $s18 = "cssNormalTransform = box[marginDiv + m + toggle + dir](result + events + dir + event);" fullword ascii
    $s19 = "ache + code + pageY + doc);" fullword ascii
    $s20 = "combinator = \"op\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}