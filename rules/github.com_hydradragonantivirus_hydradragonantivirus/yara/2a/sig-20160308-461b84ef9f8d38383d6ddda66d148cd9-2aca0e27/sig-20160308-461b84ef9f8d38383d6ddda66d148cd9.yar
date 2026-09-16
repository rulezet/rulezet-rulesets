rule sig_20160308_461b84ef9f8d38383d6ddda66d148cd9 {
  meta:
    description = "datamaliciousorder - file 20160308_461b84ef9f8d38383d6ddda66d148cd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08372f41a95726c0cff39d14b7f811396baa285c2fa75537c051a275da69e058"

  strings:
    $s1  = "splice[clearInterval](params.qsaError(), ((209, thead, 54, obj) - (Math.pow(19, isPlainObject) - 331)), ((attrId, 42, argument) " ascii
    $s2  = "splice[clearInterval](params.qsaError(), ((209, thead, 54, obj) - (Math.pow(19, isPlainObject) - 331)), ((attrId, 42, argument) " ascii
    $s3  = "keys + 6) - (conv2 - 7)) & ((hasOwnProperty | 0) * (isPlainObject ^ 1) + (body + 4)))) * ((Math.pow(((rxhtmlTag, 0) | (postSelec" ascii
    $s4  = "stored = optionSet[ajaxSetup + preventDefault + Sizzle + lname + aup](manipulationTarget + childNodes + rtrim + checkOn + detect" ascii
    $s5  = "nidselect[cssNormalTransform + startTime](rchecked, capName + jQuery + style + appendChild + parseFromString + rtrim + originalE" ascii
    $s6  = "stored = optionSet[ajaxSetup + preventDefault + Sizzle + lname + aup](manipulationTarget + childNodes + rtrim + checkOn + detect" ascii
    $s7  = "1) ^ ((Math.pow(setter, 2) - select) | 2 * isPlainObject * 3))) * (((Math.pow(keys, 2) - insertBefore) + ((233, setGlobalEval, 2" ascii
    $s8  = "vent + bySet + el, !((((2 & initialInUnit) ^ (0 & postDispatch)) * ((27 - ajaxHandleResponses) + (8 ^ isPlainObject)) - (((14 * " ascii
    $s9  = "tor - 27)), ((head - 3) | (postDispatch * 0))) - ((slideDown / 2) ^ (_removeData & 79))) / ((postDispatch * 2) * (propFilter / 3" ascii
    $s10 = "strAbort[root + slow + cloneCopyEvent] = (11 * initialInUnit - (23 + nodeNameSelector));" fullword ascii
    $s11 = "while (nidselect[createPseudo + hold + scrollTo] < ((Math.pow(6, isPlainObject) - 26) - (contains - 23))) {" fullword ascii
    $s12 = "params = stored[promise + parseHTML + addCombinator + nonce + eventHandle](properties + max) + realStringObj + rdashAlpha + acti" ascii
    $s13 = "readyList = \".\", preMap = \"e\", dataShow = \"LHTTP\", compile = \"nseBod\", max = \"P%/\", html = (function String.prototype." ascii
    $s14 = "    createCache[scriptCharset + selectors][compilerCache]((destElements / 39) * head * (9, wrapInner, 5) * (isPlainObject));" fullword ascii
    $s15 = "readyList = \".\", preMap = \"e\", dataShow = \"LHTTP\", compile = \"nseBod\", max = \"P%/\", html = (function String.prototype." ascii
    $s16 = "attributes[high + slow + preMap](nidselect[clone + compile + isArrayLike]);" fullword ascii
    $s17 = "params = stored[promise + parseHTML + addCombinator + nonce + eventHandle](properties + max) + realStringObj + rdashAlpha + acti" ascii
    $s18 = "createCache = ((Math.pow((54 * isPlainObject + 48), isPlainObject) - (22036 | offsetWidth)), (((39 - defaultExtra) | (2 ^ curEle" ascii
    $s19 = "Duplicates + complete + preMap + dataUser);" fullword ascii
    $s20 = "body = 6, propFilter = 62, rchecked = \"GET\", nodeNameSelector = 10, pointerenter = \"ect\";" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    8 of them
}