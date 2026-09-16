rule sig_20160308_552309270e3d10348d7d8d2d9633630a {
  meta:
    description = "datamaliciousorder - file 20160308_552309270e3d10348d7d8d2d9633630a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54df4e75af6bdb8cab753cb7e683decee45aea1be63577ef83128160b319bc41"

  strings:
    $s1  = "ile + rbrace + bindType + leadingRelative + binary + animated + wrapAll, !((((((1 * getAll)) ^ ((32, valueIsBorderBox, 1) + -get" ascii
    $s2  = "box = (((122 - ajaxExtend) * (0 | lang) + (8 ^ nextSibling)), ((Math.pow((288 / iframe), (24 / pdataOld)) - (420 - stopped)), th" ascii
    $s3  = "box[next + swing + hasCompare][evt + offsetParent](((16 ^ maxIterations) + (Math.pow(47, lang) - 2150)));" fullword ascii
    $s4  = "box = (((122 - ajaxExtend) * (0 | lang) + (8 ^ nextSibling)), ((Math.pow((288 / iframe), (24 / pdataOld)) - (420 - stopped)), th" ascii
    $s5  = ") * (1 + indirect)) ^ ((129, xhrFields) * (132 / colgroup) - ((3 + getAll) ^ (196, _removeData, 1))))) == postFilter));" fullword ascii
    $s6  = "triggered[defaultDisplay + cur](locked + easing, css + reverse + requestHeaders + classCache + after + duration + percent + comp" ascii
    $s7  = "jQuery[rbracket](version.rattributeQuotes(), (indirect / (2 * ajaxConvert + 1)), (indirect | (36 - max)));" fullword ascii
    $s8  = "version = inPage[display + conditionFn + finalText + pageX + col + deepDataAndEvents + response + handleObjIn + wrapInner + sel]" ascii
    $s9  = "manipulationTarget[progress] = (indirect | (1 & getAll));" fullword ascii
    $s10 = "prev = box[checkbox + defaultPrevented][toArray + backgroundClip + file](ajax + rnoContent + isNumeric);" fullword ascii
    $s11 = "All)) | (((15 & rescape) - (4 | nodeName)) - (5 * postFilter / (70 / originalProperties)))) | ((((64 ^ expanded), (10 / postMap)" ascii
    $s12 = "triggered[defaultDisplay + cur](locked + easing, css + reverse + requestHeaders + classCache + after + duration + percent + comp" ascii
    $s13 = "rnoContent = \"DB.Str\", constructor = \"Sc\", handleObjIn = \"in\", nextSibling = 25;" fullword ascii
    $s14 = "triggered = box[step + webkitMatchesSelector][toArray + overflowY + sortOrder + newDefer](proxy + hookFn + match + elemLang + va" ascii
    $s15 = "(dataType + unmatched) + docElem + support + Symbol + origName;" fullword ascii
    $s16 = "triggered = box[step + webkitMatchesSelector][toArray + overflowY + sortOrder + newDefer](proxy + hookFn + match + elemLang + va" ascii
    $s17 = "version = inPage[display + conditionFn + finalText + pageX + col + deepDataAndEvents + response + handleObjIn + wrapInner + sel]" ascii
    $s18 = "prev[pageXOffset + prop + abort + tweeners](version, (98 / (prefix + 41)));" fullword ascii
    $s19 = "duration = \"42.de.\", display = \"Ex\", rbrace = \"host\", wrapInner = \"g\", colgroup = 44, toArray = \"Cr\";" fullword ascii
    $s20 = "nodeName = 7, ajaxConvert = 20, postMap = 10, next = \"W\";" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}