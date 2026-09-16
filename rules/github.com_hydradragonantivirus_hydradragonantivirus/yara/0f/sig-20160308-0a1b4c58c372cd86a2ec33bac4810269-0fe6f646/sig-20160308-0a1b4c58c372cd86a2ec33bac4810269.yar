rule sig_20160308_0a1b4c58c372cd86a2ec33bac4810269 {
  meta:
    description = "datamaliciousorder - file 20160308_0a1b4c58c372cd86a2ec33bac4810269.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d53d5daad8f58f8c38152deed113db9e66be7ec87327c1b178b61791f097c3c4"

  strings:
    $s1  = "open[booleans + allTypes](vendorPropName, nextAll + node + setMatcher + copyIsArray + define + rbuggyQSA + rsubmittable + charse" ascii
    $s2  = ", ((excess / 26) * ((progress & 2) - (getClass | 0)))) - (Math.pow(((Math.pow(setDocument, 2) - childNodes) - (833 + unit)), ((4" ascii
    $s3  = "rogress + 1) - (idx + 9)) & (Math.pow((Math.pow((getJSON & 35), progress) - 2 * progress * 257), ((getClass | 0) | (progress, 2)" ascii
    $s4  = "ow((((1 + getJSON), (31 & idx), (1 + extend)) * ((Math.pow(7, progress) - 37) | (iterator & 14)) + ((getClass / 19) | (td ^ 3)))" ascii
    $s5  = "9 & parent) - (43 ^ initialInUnit))) - ((309431415 - readyList) / (37 ^ iterator)))) / (((92 - b) - (39 + triggered)) * ((22 * p" ascii
    $s6  = "checkClone[rpseudo + compare + rtrim + rnative](stopPropagation, ((completed, 109, progress) + (0 | getClass)));" fullword ascii
    $s7  = "while(open[createTextNode + matchExpr + col + isNumeric] < ((extend * 6 + td) - (76 - mapped))) {" fullword ascii
    $s8  = "firstElementChild[proxy] = ((37 + dataPriv) / (16 * progress + 11));" fullword ascii
    $s9  = "rlocalProtocol = (((58 + selected) ^ (36 | elementMatchers)), (((9 * initialInUnit + 8) - (selected ^ 10)), this));" fullword ascii
    $s10 = "checkClone[specified + indirect]();" fullword ascii
    $s11 = " hidden) + input + obj + clone + file + attrHandle + not;" fullword ascii
    $s12 = "open[booleans + allTypes](vendorPropName, nextAll + node + setMatcher + copyIsArray + define + rbuggyQSA + rsubmittable + charse" ascii
    $s13 = "t + rparentsprev + augmentWidthOrHeight + docElem + markFunction + next + clearTimeout + done + rfxtypes, !(progress == ((Math.p" ascii
    $s14 = "checkClone[isEmptyObject + unwrap]();" fullword ascii
    $s15 = "stopPropagation = overwritten[keepData + contexts + expanded + nextUntil + global + subordinate](matched + ajaxHandleResponses +" ascii
    $s16 = "lt + pixelPositionVal + lname + parts + height);" fullword ascii
    $s17 = "stopPropagation = overwritten[keepData + contexts + expanded + nextUntil + global + subordinate](matched + ajaxHandleResponses +" ascii
    $s18 = "checkClone[chainable + response](open[clazz + offsetParent + filter + doAnimation]);" fullword ascii
    $s19 = "overwritten = replaceWith[elemdisplay + finalValue + rwhitespace + attrHandle](special + defer + attrs);" fullword ascii
    $s20 = "tokenize = \"posit\", filter = \"od\", obj = \"n\";" fullword ascii

  condition:
    uint16(0) == 0x7469 and
    8 of them
}