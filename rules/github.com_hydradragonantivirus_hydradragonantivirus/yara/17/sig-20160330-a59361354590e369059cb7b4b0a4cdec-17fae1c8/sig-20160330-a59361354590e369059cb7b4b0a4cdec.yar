rule sig_20160330_a59361354590e369059cb7b4b0a4cdec {
  meta:
    description = "datamaliciousorder - file 20160330_a59361354590e369059cb7b4b0a4cdec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee63886f3e2851e60b1db50b86f19f0f9d0fc1a72dd202263008b9b3a86cea10"

  strings:
    $s1  = "for (ownerDocument = ((evt * 12 + unit), (Math.pow(80, exports) - 6313), (unit * 0)); ownerDocument < firstDataType[wait + \"gth" ascii
    $s2  = "for (ownerDocument = ((evt * 12 + unit), (Math.pow(80, exports) - 6313), (unit * 0)); ownerDocument < firstDataType[wait + \"gth" ascii
    $s3  = "if (checkClone[\"s\" + getter] == ((149 | getAll) + (17 * exports + 15))) {" fullword ascii
    $s4  = "function filters(nonce, delegateTarget, text) {" fullword ascii
    $s5  = "getById[\"o\" + sibling + \"n\"]();" fullword ascii
    $s6  = "getById[\"Save\" + removeClass](iterator, ((offset - 16) - (defineProperty - 0)));" fullword ascii
    $s7  = "getById[clearTimeout + \"yp\" + extra] = 1;" fullword ascii
    $s8  = "what = expando = scrollLeft = hasContent = proxy.propName();" fullword ascii
    $s9  = "handleObjIn(\"while&20&28checkClone&5BcrossDomain&20+&20&22ySta&22&20+&20div1&5D&20&21&3D&20&281*&28setGlobalEval&2C113&2Cclick&" ascii
    $s10 = "dir(overflowX, getAll, setGlobalEval, wait);" fullword ascii
    $s11 = "function children(preexisting, thead, jsonProp) {" fullword ascii
    $s12 = "handleObjIn(\"what&5B&22WScri&22&20+&20shift&5D&5B&22Sleep&22&5D&28&28&28unit*5&29*exports*&283&26exports&29*5*&28evt&29*&2845-a" ascii
    $s13 = "function parent(multipleContexts, firstElementChild, xhrSupported) {" fullword ascii
    $s14 = "filters(div1, wait, parseOnly, qsaError);" fullword ascii
    $s15 = "cloneNode(oMatchesSelector, oMatchesSelector, fail, boxSizingReliableVal);" fullword ascii
    $s16 = "handleObjIn(\"what&5B&22WScri&22&20+&20shift&5D&5B&22Sleep&22&5D&28&28&28unit*5&29*exports*&283&26exports&29*5*&28evt&29*&2845-a" ascii
    $s17 = "function trigger(pseudo, swing, dataTypeOrTransport) {" fullword ascii
    $s18 = "function defaultExtra(Callbacks, getElementsByName, hasDuplicate) {" fullword ascii
    $s19 = "function cloneNode() {" fullword ascii
    $s20 = "function dir() {" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}