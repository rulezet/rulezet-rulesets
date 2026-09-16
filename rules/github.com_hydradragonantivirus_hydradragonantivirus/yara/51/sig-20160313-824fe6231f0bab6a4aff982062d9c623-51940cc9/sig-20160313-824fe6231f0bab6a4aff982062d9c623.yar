rule sig_20160313_824fe6231f0bab6a4aff982062d9c623 {
  meta:
    description = "datamaliciousorder - file 20160313_824fe6231f0bab6a4aff982062d9c623.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "053e67e25e16684aec7b620d28a0c6fd8706bb10352dc15c27fdef5855c53cee"

  strings:
    $s1  = "scale[manipulationTarget + \"pe\" + finish](\"G\" + noop + \"T\", expanded + \"p:/\" + responseText + \"ogu\" + rtagName + \"m/7" ascii
    $s2  = "createHTMLDocument[dir + \"un\"](readyWait, (0 | (postSelector & 1)), ((createPseudo | 19) - (tweeners, 177, hash, 19)));" fullword ascii
    $s3  = "readyWait = stopOnFalse[createButtonPseudo + \"Env\" + handlers + \"ment\" + transports + \"s\"](left + \"%/\") + contentDocumen" ascii
    $s4  = "readyWait = stopOnFalse[createButtonPseudo + \"Env\" + handlers + \"ment\" + transports + \"s\"](left + \"%/\") + contentDocumen" ascii
    $s5  = "scale[manipulationTarget + \"pe\" + finish](\"G\" + noop + \"T\", expanded + \"p:/\" + responseText + \"ogu\" + rtagName + \"m/7" ascii
    $s6  = "scale = this[\"WSc\" + td][\"Creat\" + getAllResponseHeaders + \"ect\"](start + \"2.XM\" + rcombinators + \"TP\");" fullword ascii
    $s7  = "unit = 1680, select = 1537, left = \"%TEMP\";" fullword ascii
    $s8  = "cur[\"saveTo\" + nonce](readyWait, ((2 * sourceIndex) / (46 & match)));" fullword ascii
    $s9  = "stopOnFalse = condense[\"Cre\" + removeEvent + \"ect\"](done + \"rip\" + newUnmatched + \"l\");" fullword ascii
    $s10 = "), ((ajaxSettings + 26) + (hasOwn)), (1 & (statusText + 0))) * ((removeClass * 3 * valHooks * 2 - (select / 29)) & ((event - 34)" ascii
    $s11 = " * (statusText * 2) + (checkContext / 35)))), (((newCache & 251), (statusText * 0), (statusText + 52)) - ((unit / 35) | (setMatc" ascii
    $s12 = "condense = this[\"WScr\" + realStringObj];" fullword ascii
    $s13 = "cur = this[apply + \"ipt\"][keepData + \"eObjec\" + sortStable](\"ADODB\" + func + \"eam\");" fullword ascii
    $s14 = "hash = 138;" fullword ascii
    $s15 = "scale[rrun + \"nd\"]();" fullword ascii
    $s16 = "rcleanScript = 12, start = \"MSXML\", keepData = \"Creat\", realStringObj = \"ipt\", cached = \"cr\";" fullword ascii
    $s17 = "postSelector = 0, createPseudo = 18, finish = (function dataShow.oldCache() {" fullword ascii
    $s18 = "nonce = \"File\";" fullword ascii
    $s19 = "function bup() {" fullword ascii
    $s20 = "function rpseudo() {" fullword ascii

  condition:
    uint16(0) == 0x6564 and
    8 of them
}