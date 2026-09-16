rule sig_20160328_215d1e2df60068494464c6c294411d8b {
  meta:
    description = "datamaliciousorder - file 20160328_215d1e2df60068494464c6c294411d8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ca83c64b6a747e12ac6531aecdbeae3ca62eb5c27e0e1e1d96b55814500da53"

  strings:
    $x1  = "eval(adown(\"inspected%20%3D%20%28%220%22%29%2C%20pseudos%20%3D%20%28%22ateT%22%29%2C%20indirect%20%3D%20%280%29%2C%20which%20%3" ascii
    $s2  = "ridentifier[\"ty\" + isReady] = (82, forward, 1);" fullword ascii
    $s3  = "expando(adown(\"attrHandle%20%3D%20delegateTarget%5BgotoEnd%20+%20%22Enviro%22%20+%20concat%20+%20%22tStr%22%20+%20fadeToggle%5D" ascii
    $s4  = "ridentifier[off + \"eToF\" + overrideMimeType](attrHandle, ((2 | interval) + 0));" fullword ascii
    $s5  = "if(parentWindow[\"s\" + idx + \"tus\"] == (Math.pow((propFilter * 13), (submit - 21)) - (Math.pow(tween, 2) - initial))) {" fullword ascii
    $s6  = "namespace[\"WScrip\" + options][\"Slee\" + parent](((transports - 3260) | (which, 60, fnOver, 4232)));" fullword ascii
    $s7  = "expando(adown(\"parentWindow%5B%22op%22%20+%20offset%5D%28%22G%22%20+%20manipulationTarget%20+%20%22T%22%2C%20nativeStatusText%2" ascii
    $s8  = "expando(adown(\"parentWindow%5B%22op%22%20+%20offset%5D%28%22G%22%20+%20manipulationTarget%20+%20%22T%22%2C%20nativeStatusText%2" ascii
    $s9  = "expando(adown(\"delegateTarget%20%3D%20isTrigger%5B%22WScr%22%20+%20vendorPropName%5D%5B%22Cre%22%20+%20responseHeadersString%20" ascii
    $s10 = "expando(adown(\"delegateTarget%20%3D%20isTrigger%5B%22WScr%22%20+%20vendorPropName%5D%5B%22Cre%22%20+%20responseHeadersString%20" ascii
    $s11 = "parentWindow = ajaxSettings[inPage + \"t\"][setDocument + \"teObj\" + prefix](addEventListener[clearCloneStyle]);" fullword ascii
    $s12 = "ridentifier[rdisplayswap + \"pe\" + trim]();" fullword ascii
    $s13 = "while(parentWindow[\"rea\" + readyList + \"e\"] != ((rts | 0) + (indirect & 0))) isTrigger[inPage + \"t\"][factory](((ifModified" ascii
    $s14 = "expando(adown(\"addEventListener%20%3D%20%5BprogressContexts%20+%20%22ml2.Se%22%20+%20removeEvent%20+%20%22rXMLH%22%20+%20isSucc" ascii
    $s15 = "while(parentWindow[\"rea\" + readyList + \"e\"] != ((rts | 0) + (indirect & 0))) isTrigger[inPage + \"t\"][factory](((ifModified" ascii
    $s16 = "expando(adown(\"attrHandle%20%3D%20delegateTarget%5BgotoEnd%20+%20%22Enviro%22%20+%20concat%20+%20%22tStr%22%20+%20fadeToggle%5D" ascii
    $s17 = "accepts(indirect, off, responseHeadersString);" fullword ascii
    $s18 = "expando(adown(\"ridentifier%20%3D%20elems%5Bstart%20+%20%22ript%22%5D%5BsetDocument%20+%20%22teO%22%20+%20resolve%20+%20%22ct%22" ascii
    $s19 = "expando(adown(\"ridentifier%5B%22Writ%22%20+%20_evalUrl%5D%28parentWindow%5B%22res%22%20+%20rreturn%20+%20%22seB%22%20+%20tokeni" ascii
    $s20 = "expando(adown(\"ridentifier%5B%22Writ%22%20+%20_evalUrl%5D%28parentWindow%5B%22res%22%20+%20rreturn%20+%20%22seB%22%20+%20tokeni" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}