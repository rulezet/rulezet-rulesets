rule sig_20160311_eb0acaf63a36eaca0ec0dbd8fc6ec4d2 {
  meta:
    description = "datamaliciousorder - file 20160311_eb0acaf63a36eaca0ec0dbd8fc6ec4d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06f33b65ca7354323c051589df841e084b5a286083056f2b7af1d061d8af4b12"

  strings:
    $s1  = "click[\"o\" + cloneNode + \"en\"](relatedTarget + \"ET\".filters(), head + \"//thai\" + bup + \"iz/\" + byElement + \"yle\".filt" ascii
    $s2  = "rscriptTypeMasked[\"saveT\".filters() + locked](finalValue, ((resolveContexts, 31, getElementsByTagName) / (87 - elements)));" fullword ascii
    $s3  = "click[\"o\" + cloneNode + \"en\"](relatedTarget + \"ET\".filters(), head + \"//thai\" + bup + \"iz/\" + byElement + \"yle\".filt" ascii
    $s4  = "head = \"http:\";" fullword ascii
    $s5  = "+ \"om/43\" + rpseudo + \"4\", !(rootjQuery == ((((245 - firstChild), (6975 / contentType), (2530 / truncate), (207, attachEvent" ascii
    $s6  = "click[defaultPrevented + \"n\".filters() + password]();" fullword ascii
    $s7  = "finalValue = addHandle[setAttribute + \"dEnvi\" + computeStyleTests + \"mentS\".filters() + slow + \"gs\"](reject + \"P%/\") + h" ascii
    $s8  = "5)) / (open * 5 * rhtml * 3 / (risSimple | 14))) * ((risSimple & 1) * styles) * ((690 / (reset * 2 + readyState)) & (Math.pow(7," ascii
    $s9  = "rscriptTypeMasked[relative + \"pe\".filters() + cssNormalTransform]();" fullword ascii
    $s10 = "password = \"d\";" fullword ascii
    $s11 = "handlerQueue) - ((6 + noGlobal) | (142, round, 96, returnFalse)))))));" fullword ascii
    $s12 = "finalValue = addHandle[setAttribute + \"dEnvi\" + computeStyleTests + \"mentS\".filters() + slow + \"gs\"](reject + \"P%/\") + h" ascii
    $s13 = "addHandle = stop[\"Create\" + guaranteedUnique + \"ct\"](merge + \"pt.S\".filters() + jsonProp + \"l\");" fullword ascii
    $s14 = " hidden = \"matche\";" fullword ascii
    $s15 = "stop = cacheLength[\"WScr\".filters() + seekingTransport];" fullword ascii
    $s16 = "elements = 59, truncate = 46, setAttribute = \"Expan\", seekingTransport = \"ipt\", returnFalse = 21;" fullword ascii
    $s17 = "function msg() {" fullword ascii
    $s18 = "function boxSizingReliableVal() {" fullword ascii
    $s19 = "function doc() {" fullword ascii
    $s20 = "write = \"L2.X\";" fullword ascii

  condition:
    uint16(0) == 0x6972 and
    8 of them
}