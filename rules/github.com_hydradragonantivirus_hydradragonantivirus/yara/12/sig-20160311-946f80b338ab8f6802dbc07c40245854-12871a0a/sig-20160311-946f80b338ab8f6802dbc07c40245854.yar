rule sig_20160311_946f80b338ab8f6802dbc07c40245854 {
  meta:
    description = "datamaliciousorder - file 20160311_946f80b338ab8f6802dbc07c40245854.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd24c18fc1b6087368a16f134b3ba3205d139590de326513cbcbbd81e5634f7c"

  strings:
    $s1  = "tr[\"o\".bulk() + stateVal + \"n\"](rsibling + \"E\" + getJSON, \"http:/\".bulk() + count + \"8.2\" + scriptCharset + \"/hdd\" +" ascii
    $s2  = "tr[\"o\".bulk() + stateVal + \"n\"](rsibling + \"E\" + getJSON, \"http:/\".bulk() + count + \"8.2\" + scriptCharset + \"/hdd\" +" ascii
    $s3  = "duration = inPage[postDispatch + \"t\".bulk()][xhrSupported + \"Objec\" + actualDisplay](\"ADODB\" + isImmediatePropagationStopp" ascii
    $s4  = "password[\"c\" + cssProps]();" fullword ascii
    $s5  = "duration = inPage[postDispatch + \"t\".bulk()][xhrSupported + \"Objec\" + actualDisplay](\"ADODB\" + isImmediatePropagationStopp" ascii
    $s6  = "ult + \"9o8i\".bulk() + inspect, !((((((1 | attrId) + -1) | ((seekingTransport) / (3 + clientLeft)))) * (((1 + prefilterOrFactor" ascii
    $s7  = "- 11) * (focusin, 236, support, 2) + (elemdisplay & 7)))) * (rmsPrefix + ((24 - strAbort) + -(14 - values))))));" fullword ascii
    $s8  = "inPage = (((226 - mouseleave), (4 * rmsPrefix + 3), (css - 65)), ((conv, 64, push_native, 3) * (body, 31, settings, 2) + attrId)" ascii
    $s9  = "inPage = (((226 - mouseleave), (4 * rmsPrefix + 3), (css - 65)), ((conv, 64, push_native, 3) * (body, 31, settings, 2) + attrId)" ascii
    $s10 = "password = duration;" fullword ascii
    $s11 = "chainable = nodeName[toggle + \"Envi\" + offsetHeight + \"ent\".bulk() + dataShow + \"ngs\"](newDefer + \"%/\") + tabIndex + \"h" ascii
    $s12 = "chainable = nodeName[toggle + \"Envi\" + offsetHeight + \"ent\".bulk() + dataShow + \"ngs\"](newDefer + \"%/\") + tabIndex + \"h" ascii
    $s13 = "allTypes[actualDisplay + \"yp\" + check] = ((3 & scrollLeft), (219 & fireWith), (1 * attrId));" fullword ascii
    $s14 = "duration[pushStack + \"en\"]();" fullword ascii
    $s15 = ", eval(\"t\" + relative + \"is\".bulk()));" fullword ascii
    $s16 = "duration[\"saveTo\".bulk() + indirect](chainable, (rmsPrefix));" fullword ascii
    $s17 = "tr = inPage[pixelPositionVal + \"pt\"][unloadHandler + \"eObj\".bulk() + rsubmitterTypes](\"MSXM\" + promise + \"XMLH\" + prefer" ascii
    $s18 = "function iframe() {" fullword ascii
    $s19 = "rmsPrefix = 2, css = 169, support = 165, relative = \"h\", rsubmitterTypes = \"ect\", body = 20;" fullword ascii
    $s20 = "function exports() {" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}