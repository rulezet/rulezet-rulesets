rule sig_20160309_2f524e3cd8532a3e9fc092479ec07a9c {
  meta:
    description = "datamaliciousorder - file 20160309_2f524e3cd8532a3e9fc092479ec07a9c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2741dbde8cc9e4dd197017ac30117eab575daeacfffb7b75ec5a1cb0faeeda46"

  strings:
    $s1  = "onlyHandlers[once + empty](addBack, contextBackup + Symbol + siblingCheck + key + compareDocumentPosition + module + noConflict," ascii
    $s2  = "matches = now[charset + fixInput + rjsonp + password + preFilter](props + col + rquery + rbracket + _evalUrl + input);" fullword ascii
    $s3  = "l = matches[setAttribute + target + setMatcher + close + clientX + getClass + getJSON + onload + pixelPositionVal + postMap + _r" ascii
    $s4  = "onlyHandlers[once + empty](addBack, contextBackup + Symbol + siblingCheck + key + compareDocumentPosition + module + noConflict," ascii
    $s5  = "var target = \"x\"," fullword ascii
    $s6  = "l = matches[setAttribute + target + setMatcher + close + clientX + getClass + getJSON + onload + pixelPositionVal + postMap + _r" ascii
    $s7  = "eq = relative[first + setMatcher + clearInterval][scrollTo + emptyGet + preFilter](matcherFromGroupMatchers + context + wrap + g" ascii
    $s8  = "es * 2 - (hasClass)) - ((679 & dispatch) / (14 + overrideMimeType)))) + ((((66 - opener) | (1 * sort)) - ((493 / createDocumentF" ascii
    $s9  = "onlyHandlers = relative[filter + getClass + outerCache + overflow][createComment + trim + fx + showHide](funescape + isXML + com" ascii
    $s10 = "relative = (((177 & createTween) + 3), (((linear - 65)), this));" fullword ascii
    $s11 = "onlyHandlers = relative[filter + getClass + outerCache + overflow][createComment + trim + fx + showHide](funescape + isXML + com" ascii
    $s12 = "eq = relative[first + setMatcher + clearInterval][scrollTo + emptyGet + preFilter](matcherFromGroupMatchers + context + wrap + g" ascii
    $s13 = "relative[jsonp + map][show + setMatcher](((rmultiDash - 3074) * cssPrefixes + (2825 ^ expand)));" fullword ascii
    $s14 = "createComment = \"Cr\", funescape = \"MSX\", password = \"eO\", marginDiv = 36, props = \"WS\";" fullword ascii
    $s15 = "isXML = \"ML2.XM\", postMap = \"ring\", matcherFromGroupMatchers = \"ADOD\", context = \"B\", createTween = 213;" fullword ascii
    $s16 = "noGlobal[duration + srcElements + each] = ((matcherOut) ^ 0);" fullword ascii
    $s17 = "now = relative[preDispatch + clearInterval];" fullword ascii
    $s18 = "compareDocumentPosition = \"x.co\", curPosition = \"open\", scrollTo = \"Create\", first = \"WScri\";" fullword ascii
    $s19 = "wrap = \".St\";" fullword ascii
    $s20 = "opener = 49," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}