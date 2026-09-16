rule sig_20160329_417e543226d2cba8998febba055941c2 {
  meta:
    description = "datamaliciousorder - file 20160329_417e543226d2cba8998febba055941c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "48445548adb6232362908f15a276d794c2d729b223961ac1955fd8aabfc35745"

  strings:
    $s1  = "function view(password, isWindow, fail) {" fullword ascii
    $s2  = "        progress[cssNormalTransform + \"pt\"][getComputedStyle](((2976 / tweeners) * (390 / temp) + (164 & disconnectedMatch)));" ascii
    $s3  = "    if(parseFromString[postDispatch + \"us\"] == ((96 + jsonp) + (201 - style))) {" fullword ascii
    $s4  = "function restoreScript() {" fullword ascii
    $s5  = "function getAttributeNode(postSelector, disable, charCode) {" fullword ascii
    $s6  = "outermostContext[opt + \"od\" + prevObject] = ((113, delay) & (57 / strAbort));" fullword ascii
    $s7  = "function nodes(root) {" fullword ascii
    $s8  = "function hash(s, divStyle) {" fullword ascii
    $s9  = "    checkClone(\"while%20%28parseFromString%5B%22readyS%22%20+%20rfocusMorph%5D%20%21%3D%20%28%28animate-195%29%2C%28rhtml*2*one" ascii
    $s10 = "function rfocusable(nativeStatusText, rxhtmlTag) {" fullword ascii
    $s11 = "function checkClone(siblings) {" fullword ascii
    $s12 = "round(allTypes, preexisting, wrapMap, prevObject, xhrFields);" fullword ascii
    $s13 = "function optgroup(teardown, cleanData, response) {" fullword ascii
    $s14 = "obj = always = progress = slideUp = createElement.createDocumentFragment();" fullword ascii
    $s15 = "function matcherIn(n, tbody) {" fullword ascii
    $s16 = "function tween(extend) {" fullword ascii
    $s17 = "nodes(Symbol, strAbort, elems, window);" fullword ascii
    $s18 = "function round(specialEasing, load, css) {" fullword ascii
    $s19 = "    for(cssFn = ((31 / what) + -(17 / container)); cssFn < escapedWhitespace[hover]; cssFn++) {" fullword ascii
    $s20 = "        view(height, disconnectedMatch, isReady, byElement);" fullword ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}