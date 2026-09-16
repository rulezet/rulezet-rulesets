rule sig_20160308_37bee469cce0f3eccee2d6c2c0c5b67f {
  meta:
    description = "datamaliciousorder - file 20160308_37bee469cce0f3eccee2d6c2c0c5b67f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6549efbd17f3585d243b5547b197a50a7e60db6e48e1630cbd1427b66f04acb5"

  strings:
    $s1  = "configurable[converters](propFilter, jqXHR + insertAfter + num + returnTrue + ct + noCloneChecked + augmentWidthOrHeight + compi" ascii
    $s2  = "(scriptCharset, 120, matchers, 160)) / (Math.pow((bulk + 23), (traditional, 2)) - (wrap - 745))))) > extra));" fullword ascii
    $s3  = "sortDetached = valueIsBorderBox[getJSON + inspected + find + origType](propHooks + attrNames + addToPrefiltersOrTransports + unb" ascii
    $s4  = "configurable = completeDeferred[guid + pdataCur + mimeType][slideDown + rkeyEvent + _$](nonce + button + augmentWidthOrHeight + " ascii
    $s5  = "configurable = completeDeferred[guid + pdataCur + mimeType][slideDown + rkeyEvent + _$](nonce + button + augmentWidthOrHeight + " ascii
    $s6  = "completeDeferred = ((Math.pow((16 ^ inPage), (27 - adown)) - 3 * fx * 41), ((charset ^ 1) * (pageXOffset, 5), this));" fullword ascii
    $s7  = "lname = completeDeferred[slideUp + mimeType][slideDown + returned + pnum](parseXML + qsa + getAttributeNode);" fullword ascii
    $s8  = "sortDetached = valueIsBorderBox[getJSON + inspected + find + origType](propHooks + attrNames + addToPrefiltersOrTransports + unb" ascii
    $s9  = "triggered[isDefaultPrevented](unloadHandler.hash(), (rhtml ^ (1 + -truncate)), ((39 - stopOnFalse) ^ (216, sortInput, 43, rhtml)" ascii
    $s10 = "pseudo + pipe + noGlobal + prefix);" fullword ascii
    $s11 = "triggered[isDefaultPrevented](unloadHandler.hash(), (rhtml ^ (1 + -truncate)), ((39 - stopOnFalse) ^ (216, sortInput, 43, rhtml)" ascii
    $s12 = "completeDeferred[propHooks + toSelector][dataTypeExpression]((5 * bulk * 5, (setFilters ^ 37)));" fullword ascii
    $s13 = "completeDeferred[propHooks + toSelector][winnow + hasOwnProperty](((strAbort | 8036) ^ (completed, 243, e)));" fullword ascii
    $s14 = "while (configurable[amd + vendorPropName + origType + animation + Symbol] < ((42 - outerCache) & (5 & bulk))) {" fullword ascii
    $s15 = "t + checked + tfoot + bp) + s + queue + needsContext + documentIsHTML + size + keyCode + createDocumentFragment;" fullword ascii
    $s16 = "unloadHandler = sortDetached[globalEval + structure + startLength + parseOnly + DOMParser + rinputs + valHooks + rprotocol](tfoo" ascii
    $s17 = "percent[close + detectDuplicates] = (truncate + -1);" fullword ascii
    $s18 = "checked = \"TEMP\"," fullword ascii
    $s19 = ") & (_data & 63)) - (rhtml ^ 0))) | ((((keepData * 8 + cssExpand) - (53 & stateString)) | (1 | (not, 0))) + (((truncate + -1) | " ascii
    $s20 = "pipe = \"L\";" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}