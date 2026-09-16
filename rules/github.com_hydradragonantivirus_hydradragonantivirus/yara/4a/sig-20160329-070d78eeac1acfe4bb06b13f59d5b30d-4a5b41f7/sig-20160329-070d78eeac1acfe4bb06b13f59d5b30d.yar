rule sig_20160329_070d78eeac1acfe4bb06b13f59d5b30d {
  meta:
    description = "datamaliciousorder - file 20160329_070d78eeac1acfe4bb06b13f59d5b30d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "388303ad714517e7723ebf714d058da7f8cd8749f8d995baefac31f4af05a95c"

  strings:
    $s1  = "function preDispatch(password, setOffset, blur) {" fullword ascii
    $s2  = "  isReady(\"define%20%3D%20high%5B%22Exp%22%20+%20pdataCur%20+%20%22vir%22%20+%20noCloneChecked%20+%20%22tSt%22%20+%20end%20+%20" ascii
    $s3  = "  if (callback[hasClass + \"tus\"] == ((32 | css) * (210 / etag) + (31 - identifier))) {" fullword ascii
    $s4  = "ajaxConvert[\"ty\" + hasData + \"e\"] = ((amd & 15) - (camel / 29));" fullword ascii
    $s5  = "function attrHandle(readyList) {" fullword ascii
    $s6  = "function attrs(test, transport) {" fullword ascii
    $s7  = "  isReady(\"define%20%3D%20high%5B%22Exp%22%20+%20pdataCur%20+%20%22vir%22%20+%20noCloneChecked%20+%20%22tSt%22%20+%20end%20+%20" ascii
    $s8  = "  udataOld(qsaError, fxNow, handlers, originAnchor, selected);" fullword ascii
    $s9  = "function isReady(offsetHeight) {" fullword ascii
    $s10 = "  isReady(\"while%20%28callback%5B%22read%22%20+%20raw%20+%20%22te%22%5D%20%21%3D%20%28%2844/checkOn%29*%281+pdataOld%29%29%29%2" ascii
    $s11 = "    key[\"WScri\" + classCache][\"Sle\" + v](((7097 + lock) & (7573 - rpseudo)));" fullword ascii
    $s12 = "  isReady(\"high%20%3D%20pixelMarginRightVal%5B%22WScri%22%20+%20classCache%5D%5B%22Crea%22%20+%20rneedsContext%20+%20%22ect%22%" ascii
    $s13 = "function handleObjIn() {" fullword ascii
    $s14 = "function removeChild() {" fullword ascii
    $s15 = "function fadeOut() {" fullword ascii
    $s16 = "removeChild(rpseudo, collection);" fullword ascii
    $s17 = "pointerleave(originalSettings, css, done);" fullword ascii
    $s18 = "function dequeue(stop, firingIndex) {" fullword ascii
    $s19 = "function pointerleave(replaceWith) {" fullword ascii
    $s20 = "function udataOld(fast) {" fullword ascii

  condition:
    uint16(0) == 0x7461 and
    8 of them
}