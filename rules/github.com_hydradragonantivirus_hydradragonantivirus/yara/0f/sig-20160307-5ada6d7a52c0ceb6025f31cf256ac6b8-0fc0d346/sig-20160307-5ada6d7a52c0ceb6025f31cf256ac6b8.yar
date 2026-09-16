rule sig_20160307_5ada6d7a52c0ceb6025f31cf256ac6b8 {
  meta:
    description = "datamaliciousorder - file 20160307_5ada6d7a52c0ceb6025f31cf256ac6b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00b27f574b0347d24e6837265dd79f605a01b0772b7ec34ac8b28ae43ff07bda"

  strings:
    $x1  = "originAnchor[flatOptions](createTextNode + insertAfter, fail + requestHeaders + margin + pageY + filter + access + offsetHeight " ascii
    $s2  = "size = (((Math.pow(167, contains) - 27707) & (getScript - 65)), (((addCombinator - 6) & (matchExpr / 26)), this));" fullword ascii
    $s3  = "originAnchor = size[v + overrideMimeType + token][responses + qsaError + ofType + resolve](rneedsContext + padding + hasContent)" ascii
    $s4  = "originAnchor = size[v + overrideMimeType + token][responses + qsaError + ofType + resolve](rneedsContext + padding + hasContent)" ascii
    $s5  = "ath.pow((96 | nextSibling), 2) - (rcombinators | 9288))), (((detach ^ 245) / (nextSibling & 1)) | (contains & 2)), ((Math.pow((h" ascii
    $s6  = "mouseenter = compiled[timeout + disabled + rquery + createElement + text + nextUntil + detectDuplicates](ajaxTransport + request" ascii
    $s7  = ") / (xml / 41)), ((_data - 14) & (rnoContent - 43)))) ^ ((((reset * 4 + cors) - (15 * contains + 6)) | ((then, 1) * (childNodes " ascii
    $s8  = "rootjQuery[risSimple + implicitRelative + p](originAnchor[headers + write + selectedIndex + getWindow]);" fullword ascii
    $s9  = "originAnchor[flatOptions](createTextNode + insertAfter, fail + requestHeaders + margin + pageY + filter + access + offsetHeight " ascii
    $s10 = "compiled = pseudos[callbackExpect + start + offset + resolve](step + ret + resolve + support + getJSON + msg);" fullword ascii
    $s11 = "wait = 463177, events = 7, createCache = \"writ\", ajaxTransport = \"%TEMP%\";" fullword ascii
    $s12 = "nodeName[rdisplayswap](mouseenter.radio(), (1 * childNodes), ((1 + childNodes) + -(38 - count)));" fullword ascii
    $s13 = "matchExpr = 26, count = 37, support = \".Sh\", risSimple = \"w\", getJSON = \"el\";" fullword ascii
    $s14 = "hasContent = \"HTTP\", attrId = 21, nodes = \"ct\", access = \"ati\", insertAfter = \"T\", contains = 2;" fullword ascii
    $s15 = "tmlPrefilter & 111), (nextSibling * 2)) - (wait / 41)), ((contains ^ 237) & (dataTypeExpression & 255)), ((clearCloneStyle - 441" ascii
    $s16 = "rootjQuery = size[tweener + resolve][insertBefore + guaranteedUnique + matcherIn + nodes](isSimulated + teardown + newDefer + au" ascii
    $s17 = "rootjQuery = size[tweener + resolve][insertBefore + guaranteedUnique + matcherIn + nodes](isSimulated + teardown + newDefer + au" ascii
    $s18 = "tokenize = \"n\", padding = \"2.XML\", clientY = 459, text = \"nt\";" fullword ascii
    $s19 = "mouseenter = compiled[timeout + disabled + rquery + createElement + text + nextUntil + detectDuplicates](ajaxTransport + request" ascii
    $s20 = "size[v + isBorderBox + parentsUntil][replaceAll + buildParams]((7 & replaceChild) * (2 + childNodes) * (2 + mouseleave) * (2 ^ c" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}