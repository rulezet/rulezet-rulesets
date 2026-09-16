rule sig_20160308_058667d8539b154efdd7811fd3541a23 {
  meta:
    description = "datamaliciousorder - file 20160308_058667d8539b154efdd7811fd3541a23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89e536a905aaaf379ed1d632fc72a0cb6a5fc7b65d0aef23578a8bcfc04d3151"

  strings:
    $x1  = "easing[callback](response, nonce + fireWith + siblingCheck + window + mouseenter + setMatcher + contentType + insertBefore + fil" ascii
    $x2  = "cssExpand), (2 + pipe)) - (Math.pow(87, argument) - 7480)) - ((curOffset - 12), (map & 103), (Math.pow(relatedTarget, 2) - addCl" ascii
    $s3  = "ames))) / ((0 ^ pipe) | (98 / parts)) * ((4 ^ pipe) * (26 - rheader) + (1 + argument)) * (49 - risSimple)) + (((Math.pow((120 / " ascii
    $s4  = "dest[isFunction](overflow.noCloneChecked(), (0 / temp), ((18 * argument + 1) - (urlAnchor, 37)));" fullword ascii
    $s5  = "  transports[html + fireWith][host + id]((argument + 0) * (pipe ^ 2) * (argument * 2 + setFilters) * 5);" fullword ascii
    $s6  = "lang[completeDeferred + tabIndex + emptyGet](overflow, ((2 + pipe) / (1 * setFilters)));" fullword ascii
    $s7  = "dle) ^ (88 | optionSet)) + (Math.pow((76 - setPositiveNumber), (1 * argument)) - ((216 ^ bindType) ^ (139, stopOnFalse)))) / (((" ascii
    $s8  = "Math.pow(((Math.pow(57, argument) - 3189) ^ (sortDetached - 157)), ((win - 34) & argument)) - ((6615 - attrHooks) + (341 ^ attrN" ascii
    $s9  = "easing = transports[fixHooks + special][holdReady + test + newSelector + serialize + unbind + fireWith](isArrayLike + hasOwn + a" ascii
    $s10 = "easing = transports[fixHooks + special][holdReady + test + newSelector + serialize + unbind + fireWith](isArrayLike + hasOwn + a" ascii
    $s11 = "jQuery = transports[hasContent + slow + errorCallback + special];" fullword ascii
    $s12 = "box = \"e\", bindType = 344, firingIndex = \"%TEMP%\";" fullword ascii
    $s13 = "raw[marginDiv + i] = ((0 ^ pipe) | (96, map, 43, setFilters));" fullword ascii
    $s14 = "ass), (10 & original))) * (((23 - keyCode) & (1 * setFilters)) ^ ((0 ^ setFilters) * 0)))) == ((((Math.pow(rescape, 2) - attrHan" ascii
    $s15 = "overflow = inspect[rdisplayswap + getWidthOrHeight + actualDisplay + postFilter + doAnimation + nodeNameSelector](firingIndex + " ascii
    $s16 = "overflow = inspect[rdisplayswap + getWidthOrHeight + actualDisplay + postFilter + doAnimation + nodeNameSelector](firingIndex + " ascii
    $s17 = "ter + prevObject, !((((setFilters * ((1 + -setFilters) ^ (1 * invert))) & (((1 * invert) & (1 + argument)) & (3 & invert))) * ((" ascii
    $s18 = "lang = transports[method + id + fireWith][firstChild + showHide + fireWith + initial + progress](tr + getClass + ajaxSettings);" fullword ascii
    $s19 = "lang[mapped + t + fadeToggle](easing[el + tag + addCombinator]);" fullword ascii
    $s20 = "inspect = jQuery[left + tmp + unbind + fireWith](html + outermostContext + triggerHandler + optgroup);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}