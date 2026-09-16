rule sig_20160308_b92e3f5aa1b1706c731bdc10c7fe7506 {
  meta:
    description = "datamaliciousorder - file 20160308_b92e3f5aa1b1706c731bdc10c7fe7506.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a748408a4ab1f4aa97b2f09b5a26ed8fd97f4dfbe9ec5cb5c5941ec8615cb133"

  strings:
    $s1  = "stored[dirruns + using](nType, ((Math.pow(50, handler) - 2430) / (Math.pow(simple, 2) - relatedTarget)));" fullword ascii
    $s2  = "conv2[cssExpand + button](rtagName, flatOptions + parseHTML + onreadystatechange + _data + jsonProp + children + show + headers," ascii
    $s3  = "operator = ((0 / (Math.pow(rbuggyMatches, 2) - clientY)), ((1 * (swap / 14)), this));" fullword ascii
    $s4  = "webkitMatchesSelector[s](nType.dataShow(), ((Math.pow(4, handler) - 11), (window / 28), (scrollTo, 163, keepData, 119), (swap / " ascii
    $s5  = "webkitMatchesSelector[s](nType.dataShow(), ((Math.pow(4, handler) - 11), (window / 28), (scrollTo, 163, keepData, 119), (swap / " ascii
    $s6  = "nType = elements[target + tween + preexisting + bySet + readyState + open](globalEval + ajaxConvert) + camelCase + root + height" ascii
    $s7  = "nType = elements[target + tween + preexisting + bySet + readyState + open](globalEval + ajaxConvert) + camelCase + root + height" ascii
    $s8  = " !(getClientRects < (((((99, max, 68), (rnamespace | 26), (simple + 8), (handler * 16 + name)) - ((32 | rbuggyQSA) & (50 + getCl" ascii
    $s9  = "parseHTML = \"tp://\", rtagName = \"GET\", postSelector = \"Respon\", document = \"LHTTP\", offsetHeight = (function String.prot" ascii
    $s10 = "while(conv2[callback + cleanData + acceptData] < (Math.pow((1 ^ handler), (1 ^ opts)) - (5 | getClientRects))) {" fullword ascii
    $s11 = "operator[reverse + handlerQueue + iframe][scrollTop + slow + first](((70 | statusText) + (13 & marginRight)));" fullword ascii
    $s12 = "conv2[cssExpand + button](rtagName, flatOptions + parseHTML + onreadystatechange + _data + jsonProp + children + show + headers," ascii
    $s13 = "curCSSLeft = operator[original + iframe];" fullword ascii
    $s14 = "globalEval = \"%TEMP%\";" fullword ascii
    $s15 = "3) ^ ((originalProperties, 142, opts) & (46 - fnOver))) - ((Math.pow((11 ^ next), (1 * handler)) - (923 - chainable)), 2 * (pars" ascii
    $s16 = "ed, 220, display, 3) * (handler | 3) * (name + 1) * handler * 3, ((trim ^ 38) & (param - 0)), (Math.pow((opts | 4), (handler ^ 0" ascii
    $s17 = "target = \"Expan\";" fullword ascii
    $s18 = "before = 20, height = \".scr\", originalProperties = 66, onreadystatechange = \"kok\", nodeType = 79, ownerDocument = \"c\";" fullword ascii
    $s19 = "parsed = 67, appendTo = 4, original = \"WScri\", relatedTarget = 494;" fullword ascii
    $s20 = "operator[node + src][doScroll + detach + offsetHeight](((3017 * appendTo + 2932)));" fullword ascii

  condition:
    uint16(0) == 0x6574 and
    8 of them
}