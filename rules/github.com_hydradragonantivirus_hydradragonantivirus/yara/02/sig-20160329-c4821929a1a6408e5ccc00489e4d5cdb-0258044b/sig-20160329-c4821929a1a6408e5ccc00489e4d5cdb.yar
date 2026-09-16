rule sig_20160329_c4821929a1a6408e5ccc00489e4d5cdb {
  meta:
    description = "datamaliciousorder - file 20160329_c4821929a1a6408e5ccc00489e4d5cdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7796dd05b2c471a5f933f1f793c80d7f9bead754740ab480768f7d0c48810a8e"

  strings:
    $s1  = "comma%20+%20%220%22%2CpreferredDoc%20+%20%22.XML%22%20+%20getBoundingClientRect%20+%20%22.0%22%2C%20letterSpacing%20+%20%222.XM%" ascii
    $s2  = " condense(\"expanded%5BdisableScript%20+%20%22pe%22%20+%20set%5D%28%22G%22%20+%20rlocalProtocol%2C%20%22http%3A/%22%20+%20elemdi" ascii
    $s3  = " condense(\"expanded%5BdisableScript%20+%20%22pe%22%20+%20set%5D%28%22G%22%20+%20rlocalProtocol%2C%20%22http%3A/%22%20+%20elemdi" ascii
    $s4  = " if(expanded[statusText + \"us\"] == ((Math.pow(callbackContext, 2) - wait) * (152 / rxhtmlTag) + (3 * addClass + 1))) {" fullword ascii
    $s5  = " for(l = (0 | abort); l < complete[\"len\" + handlers]; l++) {" fullword ascii
    $s6  = " condense(\"complete%20%3D%20%5B%22Msxm%22%20+%20cache%20+%20%22rverX%22%20+%20swap%20+%20%22TP.6.%22%20+%20bp%2C%20%22Msxml2%22" ascii
    $s7  = "   expanded = isImmediatePropagationStopped[\"WScrip\" + pageY][\"Cre\" + textContent + \"ect\"](complete[l]);" fullword ascii
    $s8  = " condense(\"cors%28%22http%3A/%22%20+%20elemdisplay%20+%20%22der%22%20+%20constructor%20+%20%22any.n%22%20+%20pixelMarginRight%2" ascii
    $s9  = "function createElement(isArrayLike, rscriptType) {" fullword ascii
    $s10 = "function isTrigger(inspectPrefiltersOrTransports, token, ridentifier) {" fullword ascii
    $s11 = "isEmptyObject = pnum = isImmediatePropagationStopped = trigger = reliableMarginLeft.postDispatch();" fullword ascii
    $s12 = "  responseFields[matchContext](expanded[\"respon\" + preDispatch + \"ody\"]);" fullword ascii
    $s13 = "  insertAfter[\"R\" + then](innerText);" fullword ascii
    $s14 = " condense(\"cors%28%22http%3A/%22%20+%20elemdisplay%20+%20%22der%22%20+%20constructor%20+%20%22any.n%22%20+%20pixelMarginRight%2" ascii
    $s15 = "function filter(opener, username, tokens) {" fullword ascii
    $s16 = "play%20+%20%22derc%22%20+%20exports%20+%20%22ny.n%22%20+%20selectedIndex%20+%20%227AUxY.%22%20+%20onlyHandlers%2C%20%21%28%28%28" ascii
    $s17 = "   filter(related, nextSibling, blur, disableScript, disableScript);" fullword ascii
    $s18 = "function backgroundClip() {" fullword ascii
    $s19 = "function uniqueID() {" fullword ascii
    $s20 = " condense(\"insertAfter%20%3D%20trigger%5B%22WScr%22%20+%20beforeSend%5D%5B%22Creat%22%20+%20easing%20+%20%22ect%22%5D%28webkitM" ascii

  condition:
    uint16(0) == 0x7363 and
    8 of them
}