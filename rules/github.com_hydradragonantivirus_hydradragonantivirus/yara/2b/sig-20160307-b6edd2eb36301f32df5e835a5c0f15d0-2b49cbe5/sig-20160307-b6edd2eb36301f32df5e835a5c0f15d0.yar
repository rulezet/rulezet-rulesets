rule sig_20160307_b6edd2eb36301f32df5e835a5c0f15d0 {
  meta:
    description = "datamaliciousorder - file 20160307_b6edd2eb36301f32df5e835a5c0f15d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c125702485447ebdc53ec17ff969d1387401a0101aafbd3d2be19def983890bf"

  strings:
    $s1  = "relative[vendorPropName + rneedsContext](fireGlobals, ajaxConvert + fontWeight + cssHooks + matches + getAttributeNode + context" ascii
    $s2  = "relative = get[cur + fnOut + valHooks + jQuery][checked + parseHTML + elementMatchers + n](url + fx + tmp + keyCode + defer);" fullword ascii
    $s3  = "rscriptType[createElement + readyWait] = ((116 & lastChild), 3 * memory * 7, (first - 42));" fullword ascii
    $s4  = "close = get[getter + once][writable + elementMatchers + animated + global](operator + selector + timeoutTimer);" fullword ascii
    $s5  = "get = (((54 - arr) + 2 * divStyle * 19), (display, this));" fullword ascii
    $s6  = "close[isReady + rattributeQuotes](relative[startTime + animated + fragment + getClientRects]);" fullword ascii
    $s7  = "134 / resolveWith), (49 / state))) ^ (((Math.pow((6, aup, 162, handleObjIn), (28 - resolveWith)) - (33 ^ wait)) | ((3 + removePr" ascii
    $s8  = "while (relative[returnFalse + XMLHttpRequest + curTop + siblings] < ((_jQuery, 218, write, 17) - (setTimeout & 13))) {" fullword ascii
    $s9  = "relative[vendorPropName + rneedsContext](fireGlobals, ajaxConvert + fontWeight + cssHooks + matches + getAttributeNode + context" ascii
    $s10 = "get[getter + once][val + valHooks]((removeProp * 5 * divStyle * 5 * divStyle / (5 + display)));" fullword ascii
    $s11 = "get[getter + once][margin + ajaxHandleResponses](((1750 / owner), (123, boxSizingReliable, 44, isWindow)));" fullword ascii
    $s12 = "shift[width](hasData.optgroup(), (memory * 3 - (extend | 1)), ((addBack, 1) & (display & 1)));" fullword ascii
    $s13 = "clientY = dataTypes[writable + elementMatchers + n](contextBackup + rquery + returnFalse + qsaError + cssFn + pageYOffset);" fullword ascii
    $s14 = "hasData = clientY[div + pixelPositionVal + ajaxTransport + animated + createPseudo + anim + push_native](rnative + clientLeft) +" ascii
    $s15 = "ents / 15) | (nType ^ 10))), (((Expr + 107) / (resolveWith & 25)) | ((toArray + 1) | (focus * 4 + which))), ((65 + compiled), (4" ascii
    $s16 = "hasData = clientY[div + pixelPositionVal + ajaxTransport + animated + createPseudo + anim + push_native](rnative + clientLeft) +" ascii
    $s17 = "} catch (manipulationTarget) {};" fullword ascii
    $s18 = "var getter = \"WScri\";" fullword ascii
    $s19 = "operator = \"ADODB\";" fullword ascii
    $s20 = "resolveWith = 26, getAttributeNode = \".uk\", selector = \".Strea\", cur = \"WSc\", jQuery = \"t\";" fullword ascii

  condition:
    uint16(0) == 0x6e66 and
    8 of them
}