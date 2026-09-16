rule sig_20160308_08e66d298d6ce4e91ecbd741b05f17b1 {
  meta:
    description = "datamaliciousorder - file 20160308_08e66d298d6ce4e91ecbd741b05f17b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "844a17b04ad30ab9073e26939c00160124e788369062f30ce561b1bc834b0a6b"

  strings:
    $x1  = "rnoContent[mouseHooks](grep, optgroup + origType + high + tweeners + div + createHTMLDocument + rcleanScript + wait + conv2 + fa" ascii
    $s2  = "emptyGet[i](rnoContent[rnotwhite + seekingTransport + proxy]);" fullword ascii
    $s3  = "reliableMarginRight[clazz + attrNames][getAttributeNode + appendChild]((Math.pow((22 * onreadystatechange + 12), (tr, 2)) - (abo" ascii
    $s4  = "reliableMarginRight = (((104, rscriptTypeMasked) ^ (437 - identifier)), (((8 - currentValue) + (1 + overflowX)), this));" fullword ascii
    $s5  = "rnoContent[mouseHooks](grep, optgroup + origType + high + tweeners + div + createHTMLDocument + rcleanScript + wait + conv2 + fa" ascii
    $s6  = "(((216 / (postDispatch | 36)) & (onlyHandlers + (1 + overflowX))) * (0 ^ onlyHandlers) + (((30 & pseudo) - (15 & props)) ^ ((17 " ascii
    $s7  = "while(rnoContent[checkOn + dir] < ((46 & rjsonp) - (74 - unshift))) {" fullword ascii
    $s8  = "emptyGet[progressContexts + swing + conditionFn + margin](xml, ((3 & onreadystatechange) | 2));" fullword ascii
    $s9  = "hasOwn[clientY](xml.isReady(), ((submit - 33) | (scrollTo - 30)), (overflowX | 0));" fullword ascii
    $s10 = "deToggle, !((((0 ^ onreadystatechange) ^ (((35, bind, 8)) | ((prototype ^ 0) * onreadystatechange * 2 * onreadystatechange))) & " ascii
    $s11 = "conv2 = \"86j5h\", seekingTransport = \"ns\", rcleanScript = \"ko.cz/\", dataType = \"type\", props = 15, margin = \"ile\";" fullword ascii
    $s12 = "rnoContent = reliableMarginRight[setTimeout + _ + settings][hold + test + noBubble + random + test](ajaxHandleResponses + guid +" ascii
    $s13 = "rnoContent = reliableMarginRight[setTimeout + _ + settings][hold + test + noBubble + random + test](ajaxHandleResponses + guid +" ascii
    $s14 = "emptyGet = reliableMarginRight[clazz + attrNames][truncate + duplicates + load](initialInUnit + fired + cache + noGlobal + wrapI" ascii
    $s15 = "emptyGet = reliableMarginRight[clazz + attrNames][truncate + duplicates + load](initialInUnit + fired + cache + noGlobal + wrapI" ascii
    $s16 = "selectedIndex[createInputPseudo + css + mapped] = ((22 / remove) * (1 + -prototype));" fullword ascii
    $s17 = "reliableMarginRight[clazz + attrNames][modified](((focusin, 227, completed, 12872) ^ (sibling ^ 3178)));" fullword ascii
    $s18 = "iframe = reliableMarginRight[position + test];" fullword ascii
    $s19 = "xml = types[urlAnchor + rclass + isNumeric + preFilter + hasScripts + offsetParent + ajaxSetup](specified + inArray + flag) + ma" ascii
    $s20 = "xml = types[urlAnchor + rclass + isNumeric + preFilter + hasScripts + offsetParent + ajaxSetup](specified + inArray + flag) + ma" ascii

  condition:
    uint16(0) == 0x6f63 and
    1 of ($x*) and 4 of them
}