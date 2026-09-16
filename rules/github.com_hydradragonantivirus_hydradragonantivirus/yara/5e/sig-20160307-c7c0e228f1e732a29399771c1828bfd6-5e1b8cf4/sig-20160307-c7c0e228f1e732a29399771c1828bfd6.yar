rule sig_20160307_c7c0e228f1e732a29399771c1828bfd6 {
  meta:
    description = "datamaliciousorder - file 20160307_c7c0e228f1e732a29399771c1828bfd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bff15f68a34a67881a60e7b7cfc1ed651ccfab45c4b675d0f97891b0fd8f7cfe"

  strings:
    $s1  = "globalEval[inspectPrefiltersOrTransports + open](rnative + parentOffset, setGlobalEval + width + valueIsBorderBox + which + writ" ascii
    $s2  = "ment | 43)))) - (((adown & 511) & (getAttributeNode | 375)) & (Math.pow((getPropertyValue), 2) - (soFar & 126975)))) / (((docume" ascii
    $s3  = "col = (((30 & index) + (45, ajaxTransport)), (((28 * nType + 24) / (Math.pow(index, 2) - cssPrefixes)), this));" fullword ascii
    $s4  = "able + extend + wrapInner + onabort, !(((Math.pow((((90, s, 230, bulk) * (1 * curCSSLeft) + (3 ^ elementMatchers)) - 2 * (elemen" ascii
    $s5  = "nt + 0) * (curCSSLeft + 0)) + (((clone * 4), (risSimple + 101), (compilerCache - 50)) & (Math.pow(clone * 3, (rsingleTag / 38)) " ascii
    $s6  = "estHeaders + documentIsHTML + getById + close + firstDataType + contexts + tr);" fullword ascii
    $s7  = "while (globalEval[converters + content + copyIsArray] < ((3 | clone) ^ (1 ^ propName))) {" fullword ascii
    $s8  = "obalEventContext + parentOffset + forward);" fullword ascii
    $s9  = "globalEval = col[matchesSelector + nonce + matcherFromGroupMatchers][list + rnamespace + matcherFromGroupMatchers](origType + gl" ascii
    $s10 = "copyIsArray = \"e\", disableScript = 14, ajaxTransport = 177, width = \"tp:/\";" fullword ascii
    $s11 = "tMatchers | 2) * (curCSSLeft + 0) * (curCSSLeft | 0) * (document + 1) * (document * 2)), ((document * 2) ^ ((reset - 59) - (docu" ascii
    $s12 = "sibling[rnoInnerhtml + view + pixelMarginRightVal + copyIsArray](mapped, ((6 * node + 3) - (attaches / 16)));" fullword ascii
    $s13 = "globalEval[inspectPrefiltersOrTransports + open](rnative + parentOffset, setGlobalEval + width + valueIsBorderBox + which + writ" ascii
    $s14 = "col[cached + simulate][setMatcher + nonce](((15 & disableScript) * (154 / locked) + 2));" fullword ascii
    $s15 = "rbracket = \"ex\", globalEventContext = \".XMLH\", expand = \"WScrip\", rfocusMorph = \"%/\", content = \"dystat\", onlyHandlers" ascii
    $s16 = "sibling = col[cached + global + nonce + matcherFromGroupMatchers][relative + pageX + rclickable + matcherFromGroupMatchers](requ" ascii
    $s17 = "nodeType = 49, inspected = \"ronm\", forward = \"TP\";" fullword ascii
    $s18 = "sibling[isEmptyObject + stored]();" fullword ascii
    $s19 = "cssText = guaranteedUnique[relative + click + backgroundClip](throws + serializeArray + firingIndex + charCode + charCode);" fullword ascii
    $s20 = "styles[rcssNum](mapped.setAttribute(), ((elementMatchers ^ 0) ^ (document * 0)), ((document & 0) | elementMatchers));" fullword ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}