rule sig_20160329_0392ca5e35f93b70dc092503dbf0eac4 {
  meta:
    description = "datamaliciousorder - file 20160329_0392ca5e35f93b70dc092503dbf0eac4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ece6cf4a7e8d1d3cf8823a8d7dd7fbfdc838eea461b3e88fd91bd7be37a6468c"

  strings:
    $s1  = "        lastModified[support + \"ToFile\"](superMatcher, ((197, parse) + (11 - dirrunsUnique)));" fullword ascii
    $s2  = "lastModified[parseFromString + \"pe\"] = ((parse + 0) * (origName - 2));" fullword ascii
    $s3  = "function getResponseHeader(ap, transport, push_native) {" fullword ascii
    $s4  = "    if(pointerenter[split + \"t\" + booleans] == ((cssPrefixes + 33), (Math.pow(innerHTML, 2) - elemData))) {" fullword ascii
    $s5  = "function prepend(postSelector) {" fullword ascii
    $s6  = "last(initial, addToPrefiltersOrTransports, etag, rinputs);" fullword ascii
    $s7  = "function maxIterations(run, multipleContexts) {" fullword ascii
    $s8  = "function configurable(sortOrder) {" fullword ascii
    $s9  = "    origFn(\"while%20%28pointerenter%5B%22readyS%22%20+%20hold%5D%20%21%3D%20%28Math.pow%28origName%2C%20%2838-isPlainObject%29%" ascii
    $s10 = "function reliableMarginRight() {" fullword ascii
    $s11 = "function reliableMarginLeft(currentValue, fixHook) {" fullword ascii
    $s12 = "function select(tr, optall) {" fullword ascii
    $s13 = "function returnFalse(a, padding) {" fullword ascii
    $s14 = "function adjustCSS(map, originalOptions) {" fullword ascii
    $s15 = "function conditionFn(sortOrder, safeActiveElement) {" fullword ascii
    $s16 = "function origFn(div1) {" fullword ascii
    $s17 = "function optDisabled(rquickExpr, divStyle, insertBefore) {" fullword ascii
    $s18 = "        event[\"WScrip\" + eq][\"Sle\" + ontype + \"p\"](((4992 | xhrFields)));" fullword ascii
    $s19 = "    origFn(\"while%20%28pointerenter%5B%22readyS%22%20+%20hold%5D%20%21%3D%20%28Math.pow%28origName%2C%20%2838-isPlainObject%29%" ascii
    $s20 = "returnFalse(isSuccess, firstDataType, booleans, result, callbackName);" fullword ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}