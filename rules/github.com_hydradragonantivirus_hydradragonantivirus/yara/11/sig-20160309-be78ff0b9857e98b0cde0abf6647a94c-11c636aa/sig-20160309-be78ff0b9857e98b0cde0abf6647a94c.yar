rule sig_20160309_be78ff0b9857e98b0cde0abf6647a94c {
  meta:
    description = "datamaliciousorder - file 20160309_be78ff0b9857e98b0cde0abf6647a94c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0669a0297332b301f2ae5c3dde968576a147d6438340a68ce843ea8e5672e14e"

  strings:
    $s1  = "animated[open + preexisting](self, jQuery + prev + results + not + padding + getAttribute + isEmptyObject + specialEasing + doSc" ascii
    $s2  = "ine))) / (((56 / requestHeaders) ^ (11 ^ curOffset)) - ((49 & invert) | 3 * optall))) / ((((107 - firingIndex) & (26 | invert)) " ascii
    $s3  = "children = \"43w\", type = 126, postSelector = \"cript\", implementation = \".scr\", requestHeaders = 28;" fullword ascii
    $s4  = "removeEvent = document[firing + until + useCache + conditionFn + ajax](scripts + qsa + postSelector + attr + offset);" fullword ascii
    $s5  = "- ((1 * sibling) * (5 + write) + 1)) & ((fireWith * 2 | (raw)) - ((15 ^ pageX) | (80 - dirrunsUnique))))) > 1));" fullword ascii
    $s6  = "events = animated[slideUp + statusText + using + rscriptTypeMasked];" fullword ascii
    $s7  = "document = realStringObj[rpseudo + contents + opt];" fullword ascii
    $s8  = "animated[open + preexisting](self, jQuery + prev + results + not + padding + getAttribute + isEmptyObject + specialEasing + doSc" ascii
    $s9  = "animated = realStringObj[push_native + ajax][handleObjIn + arg + unique](getPropertyValue + tuple + noop + testContext);" fullword ascii
    $s10 = "rpseudo = \"WS\", scripts = \"W\", writable = \"B.Str\";" fullword ascii
    $s11 = "uniqueCache = removeEvent[curCSSTop + isBorderBox + load + rCRLF + qsa + cssNumber + shift + triggerHandler](cacheLength + getPr" ascii
    $s12 = "opertyValue + isDefaultPrevented + href + set) + radio + compareDocumentPosition + JSON + triggerHandler + implementation;" fullword ascii
    $s13 = "iframe = \"Run\", isEmptyObject = \"/syste\", cssNumber = \"tri\", load = \"onme\";" fullword ascii
    $s14 = "curCSSTop = \"Expan\", createTween = \"type\", contents = \"cri\", curOffset = 109, scrollLeft = \"oFile\", preexisting = \"pen" ascii
    $s15 = "forward = \"open\";" fullword ascii
    $s16 = "uniqueCache = removeEvent[curCSSTop + isBorderBox + load + rCRLF + qsa + cssNumber + shift + triggerHandler](cacheLength + getPr" ascii
    $s17 = "roll + handle + children + updateFunc, !((((((ct & 228335) / rsubmittable * 2) & ((pos, 169, type, 4279) + (valueParts, 118, def" ascii
    $s18 = "realStringObj = (((32 + msMatchesSelector) & (79 ^ start)), (((0 ^ firstElementChild) * 2), this));" fullword ascii
    $s19 = "swap[createTween] = (write | (1 * firstElementChild));" fullword ascii
    $s20 = "rtagName[clientTop + always + padding] = 0;" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}