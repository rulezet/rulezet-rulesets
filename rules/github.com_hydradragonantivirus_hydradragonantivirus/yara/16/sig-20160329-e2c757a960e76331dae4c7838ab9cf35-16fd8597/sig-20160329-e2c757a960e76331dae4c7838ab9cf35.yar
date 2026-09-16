rule sig_20160329_e2c757a960e76331dae4c7838ab9cf35 {
  meta:
    description = "datamaliciousorder - file 20160329_e2c757a960e76331dae4c7838ab9cf35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6830bca248795435eded7cd7198a0ae7b32a5e2a70d8c12dfdedbbd7d5a2c19f"

  strings:
    $s1  = "firstElementChild[getElementsByName + \"e\"](addEventListener[binary + \"nseBod\" + defaultPrevented]);" fullword ascii
    $s2  = "preFilter(\"while%20%28addEventListener%5Bgroups%20+%20%22yStat%22%20+%20rsingleTag%5D%20%21%3D%20%28Math.pow%28%28firstChild%29" ascii
    $s3  = "if (addEventListener[\"sta\" + getAll] == ((201 & subordinate) | (2 * max * 2 * off * 5))) {" fullword ascii
    $s4  = "preFilter(\"cached%20%3D%20stateVal%5Btargets%20+%20%22dEnvi%22%20+%20postDispatch%20+%20%22entStr%22%20+%20option%5D%28%22%25TE" ascii
    $s5  = "showHide(detach, setOffset, iframe, rkeyEvent);" fullword ascii
    $s6  = "originAnchor[\"WSc\" + iframe][\"Sleep\"](((module & 7080) | (setFilters & 8182)));" fullword ascii
    $s7  = "firstElementChild[complete + \"y\" + fadeTo] = ((42 + indirect), (1 & check));" fullword ascii
    $s8  = "preFilter(\"while%20%28addEventListener%5Bgroups%20+%20%22yStat%22%20+%20rsingleTag%5D%20%21%3D%20%28Math.pow%28%28firstChild%29" ascii
    $s9  = "preFilter(\"cached%20%3D%20stateVal%5Btargets%20+%20%22dEnvi%22%20+%20postDispatch%20+%20%22entStr%22%20+%20option%5D%28%22%25TE" ascii
    $s10 = "function excess(attrHooks, next, rscriptTypeMasked) {" fullword ascii
    $s11 = "function parseHTML(rnoContent) {" fullword ascii
    $s12 = "preFilter(\"pixelMarginRightVal%28%22http%3A%22%20+%20replaceChild%20+%20%22hop%22%20+%20disableScript%20+%20%22kes%22%20+%20cal" ascii
    $s13 = "function margin(defaultDisplay, contentType, nodeType) {" fullword ascii
    $s14 = "preFilter(\"pixelMarginRightVal%28%22http%3A%22%20+%20replaceChild%20+%20%22hop%22%20+%20disableScript%20+%20%22kes%22%20+%20cal" ascii
    $s15 = "for (load = (24 - siblingCheck); load < caption[\"length\"]; load++) {" fullword ascii
    $s16 = "preFilter(\"firstElementChild%5BmaxIterations%20+%20%22de%22%5D%20%3D%20%28%283*firstChild*5*firstChild%29/%2883-completed%29%29" ascii
    $s17 = "preFilter(\"addEventListener%5BaddBack%20+%20%22e%22%20+%20elementMatchers%5D%28%22GE%22%20+%20createTween%2C%20%22htt%22%20+%20" ascii
    $s18 = "preFilter(\"firstElementChild%5BmaxIterations%20+%20%22de%22%5D%20%3D%20%28%283*firstChild*5*firstChild%29/%2883-completed%29%29" ascii
    $s19 = "preFilter(\"stateVal%20%3D%20prependTo%5B%22WScrip%22%20+%20complete%5D%5B%22Crea%22%20+%20mozMatchesSelector%20+%20%22ct%22%5D%" ascii
    $s20 = "function removeEventListener(onload) {" fullword ascii

  condition:
    uint16(0) == 0x6c6f and
    8 of them
}