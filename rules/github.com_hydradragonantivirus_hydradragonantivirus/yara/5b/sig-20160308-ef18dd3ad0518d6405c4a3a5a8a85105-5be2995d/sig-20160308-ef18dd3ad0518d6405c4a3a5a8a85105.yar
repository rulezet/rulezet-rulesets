rule sig_20160308_ef18dd3ad0518d6405c4a3a5a8a85105 {
  meta:
    description = "datamaliciousorder - file 20160308_ef18dd3ad0518d6405c4a3a5a8a85105.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88c5aa1594394eb77e78ecc823fd6e92adbcf9390f5ed45cb3ff8aa04a6af549"

  strings:
    $s1  = "step[ajax + noConflict](getClientRects, doc + firing + before + handleObj + innerText + _queueHooks + value + height + attaches " ascii
    $s2  = ") * ((6 | teardown) + (0 | teardown)) + 7)) / (((host ^ 0) * (handleObjIn | 0) * (combinator | 0) * (relatedTarget / 39) * (bp /" ascii
    $s3  = " 42) * host / (35 - timeStamp) * (76 / getAll) * (1 ^ combinator) * (102, ajaxExtend, 209, host)) + (((56 - sourceIndex) - (83 -" ascii
    $s4  = "tuples = (((102 / host) ^ (192 | createInputPseudo)), ((2 & combinator) * (42 - adjustCSS) * (1 | combinator), this));" fullword ascii
    $s5  = "+ ownerDocument, !(1 < ((((handleObjIn * 21 + marginDiv) * (0 ^ combinator) - (240, rsubmittable)) ^ ((76 / getAll) * (323 / uid" ascii
    $s6  = "submit[parse + checkNonElements + markFunction + risSimple + getWidthOrHeight](clientTop, ((41 & genFx) - (17 | context)));" fullword ascii
    $s7  = "tuples[bulk + animated][append + removeData]((61 * combinator * 3 * then & (13032 ^ getAttribute)));" fullword ascii
    $s8  = "fireWith[setMatcher + rtypenamespace + elements + allTypes] = ((1 * showHide) + -(3 - combinator));" fullword ascii
    $s9  = "original = rscriptTypeMasked[createOptions + unquoted + attrHandle + rtypenamespace](noGlobal + append + rmouseEvent + testConte" ascii
    $s10 = "original = rscriptTypeMasked[createOptions + unquoted + attrHandle + rtypenamespace](noGlobal + append + rmouseEvent + testConte" ascii
    $s11 = "current = \"am\", ownerDocument = \"b4\", getClientRects = \"GET\", createOptions = \"C\", relatedTarget = 78;" fullword ascii
    $s12 = "ies + minWidth + getAllResponseHeaders + current);" fullword ascii
    $s13 = "submit = tuples[bulk + testContext + rtypenamespace][createOptions + responseFields + settings + rtypenamespace](originalPropert" ascii
    $s14 = "step[ajax + noConflict](getClientRects, doc + firing + before + handleObj + innerText + _queueHooks + value + height + attaches " ascii
    $s15 = "submit[elementMatchers + key]();" fullword ascii
    $s16 = "host = 3;" fullword ascii
    $s17 = "step = tuples[pageXOffset + iNoClone][stop + delegateType + cached](createTween + status + rchecked + id + getElementsByName);" fullword ascii
    $s18 = "xt + rtypenamespace + isNumeric + append + height + reverse);" fullword ascii
    $s19 = "step[percent + propName]();" fullword ascii
    $s20 = "converters[handle + fireGlobals] = (1 & showHide);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}