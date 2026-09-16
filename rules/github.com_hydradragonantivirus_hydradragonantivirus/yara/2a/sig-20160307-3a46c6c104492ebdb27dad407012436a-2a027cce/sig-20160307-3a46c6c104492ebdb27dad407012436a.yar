rule sig_20160307_3a46c6c104492ebdb27dad407012436a {
  meta:
    description = "datamaliciousorder - file 20160307_3a46c6c104492ebdb27dad407012436a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "272bdd366ee44352e3e6dfe3f32fecae196b216b648fb3e8d379a122c1e06bf5"

  strings:
    $s1  = "replaceWith[setter](keyCode, list + onreadystatechange + prevObject + tokens + isBorderBox + token + target + opacity + duplicat" ascii
    $s2  = "replaceWith[setter](keyCode, list + onreadystatechange + prevObject + tokens + isBorderBox + token + target + opacity + duplicat" ascii
    $s3  = "sibling[count](chainable.createTextNode(), ((on * 0) ^ lastChild), ((37 - pageYOffset) / 2 * rootjQuery * 5));" fullword ascii
    $s4  = "target = \"imme\";" fullword ascii
    $s5  = "MAX_NEGATIVE[expand](replaceWith[getWindow + sel + height]);" fullword ascii
    $s6  = "while (replaceWith[isArrayLike + td] < ((17 * className + 5) - (Math.pow(optSelected, 2) - _queueHooks))) {" fullword ascii
    $s7  = "nodeValue = (((664 / focus), (31 & n), (33 | parseXML)), (((Math.pow(12, className) - 129) & (marginRight + 9)), this));" fullword ascii
    $s8  = "notify = \".scr\";" fullword ascii
    $s9  = "temp = \"WS\";" fullword ascii
    $s10 = "7) ^ (lastChild & 1)) - (Math.pow((clearCloneStyle, 21), (className & 3)) - (state | 407)))) == (((((Math.pow(file, 2) - round) " ascii
    $s11 = "MAX_NEGATIVE = nodeValue[temp + xhrSuccessStatus + toggleClass][inArray + callbackContext + ignored + clazz + pop](dataTypeExpre" ascii
    $s12 = "MAX_NEGATIVE = nodeValue[temp + xhrSuccessStatus + toggleClass][inArray + callbackContext + ignored + clazz + pop](dataTypeExpre" ascii
    $s13 = "replaceWith = nodeValue[uniqueSort + inPage + newSelector + pop][inArray + elem + getElementsByClassName](fadeOut + append + tag" ascii
    $s14 = "replaceWith = nodeValue[uniqueSort + inPage + newSelector + pop][inArray + elem + getElementsByClassName](fadeOut + append + tag" ascii
    $s15 = "replaceWith[soFar + all]();" fullword ascii
    $s16 = "+ (3 & eventPath)) - ((14 + timers) & (205, round, 217, callbackInverse))) & ((1 | on) & (0 ^ on))) + ((((0 ^ eventPath) ^ (Math" ascii
    $s17 = "image = nodeValue[rneedsContext + isSuccess];" fullword ascii
    $s18 = "token = \"e-h\"," fullword ascii
    $s19 = "step = \"Run\";" fullword ascii
    $s20 = "file = 15, getElementsByClassName = \"ject\", duplicates = \"/978\", callbackContext = \"eat\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}