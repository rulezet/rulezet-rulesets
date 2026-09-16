rule sig_20160328_4ecf868467a69553c0ed2bc6e50e5430 {
  meta:
    description = "datamaliciousorder - file 20160328_4ecf868467a69553c0ed2bc6e50e5430.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc3bd66454c7e97daf7011caf9b008d40335060d4af7b4a1ef18187ee0e86791"

  strings:
    $s1  = "while (aup[\"readyS\" + swap] != (Math.pow((241, document), 2) - (currentValue - 31))) slideToggle[\"WScr\" + finish][\"S\" + ge" ascii
    $s2  = "while (aup[\"readyS\" + swap] != (Math.pow((241, document), 2) - (currentValue - 31))) slideToggle[\"WScr\" + finish][\"S\" + ge" ascii
    $s3  = "version(nodeNameSelector(\"aup%5BisHidden%20+%20%22e%22%20+%20udataOld%5D%28%22G%22%20+%20rmsPrefix%20+%20%22T%22%2C%20special%2" ascii
    $s4  = "if (aup[setMatcher + \"at\" + getElementsByName] == ((finalDataType - 59) + (stop * 67))) {" fullword ascii
    $s5  = "version(nodeNameSelector(\"write%20%3D%20%5Bthead%20+%20%22ml2%22%20+%20queue%20+%20%22rXM%22%20+%20inspectPrefiltersOrTransport" ascii
    $s6  = "htmlPrefilter[showHide + \"Fil\" + andSelf](nodeValue, ((Math.pow(135, stop) - 18085), (valHooks, 51, PI), (79 + rsubmitterTypes" ascii
    $s7  = "htmlPrefilter[showHide + \"Fil\" + andSelf](nodeValue, ((Math.pow(135, stop) - 18085), (valHooks, 51, PI), (79 + rsubmitterTypes" ascii
    $s8  = "htmlPrefilter[\"Writ\" + andSelf](aup[\"resp\" + host + \"dy\"]);" fullword ascii
    $s9  = "htmlPrefilter[\"mo\" + headers] = ((3 & document));" fullword ascii
    $s10 = "for (sortDetached = ((ajaxPrefilter + -1) / (destElements + 7)); sortDetached < write[\"lengt\" + genFx]; sortDetached++) {" fullword ascii
    $s11 = "version(nodeNameSelector(\"write%20%3D%20%5Bthead%20+%20%22ml2%22%20+%20queue%20+%20%22rXM%22%20+%20inspectPrefiltersOrTransport" ascii
    $s12 = "ntsByTagName + \"ep\"]((Math.pow((all * 3 * stop), (2 + capName)) - (2092 * stop + 1800)));" fullword ascii
    $s13 = "version(nodeNameSelector(\"nodeValue%20%3D%20jqXHR%5BdefaultView%20+%20%22Envi%22%20+%20cleanData%20+%20%22entS%22%20+%20replace" ascii
    $s14 = "version(nodeNameSelector(\"htmlPrefilter%5B%22t%22%20+%20tabIndex%20+%20%22e%22%5D%20%3D%20%28%284*matchesSelector+1%29/%28valHo" ascii
    $s15 = "version(nodeNameSelector(\"htmlPrefilter%5B%22t%22%20+%20tabIndex%20+%20%22e%22%5D%20%3D%20%28%284*matchesSelector+1%29/%28valHo" ascii
    $s16 = "function nodeNameSelector(getAll) {" fullword ascii
    $s17 = "aup = matchedCount[\"WScr\" + finish][\"Creat\" + pop + \"ct\"](write[sortDetached]);" fullword ascii
    $s18 = "version(nodeNameSelector(\"htmlPrefilter%20%3D%20deepDataAndEvents%5B%22WScr%22%20+%20finish%5D%5B%22Crea%22%20+%20vendorPropNam" ascii
    $s19 = "function isTrigger(dirrunsUnique, scrollTop) {" fullword ascii
    $s20 = "version(nodeNameSelector(\"matchedCount%5B%22WScri%22%20+%20next%5D%5B%22S%22%20+%20hide%20+%20%22e%22%20+%20andSelf%20+%20%22p%" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}