rule sig_20160329_d20550a49ec2cd68338b6ff653a165fc {
  meta:
    description = "datamaliciousorder - file 20160329_d20550a49ec2cd68338b6ff653a165fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295321e321dca7152cd6804fa39a720c13f31e81b5ce99e39bab5061a9c2c3ca"

  strings:
    $s1  = "keepScripts(thead, fnOver, Sizzle);" fullword ascii
    $s2  = "function keepScripts(simple, dataUser, each) {" fullword ascii
    $s3  = "handleObj[\"t\" + visibility + \"e\"] = ((stored & 51) - (special & 39));" fullword ascii
    $s4  = "for(rclass = (manipulationTarget & (61, what)); rclass < removeProp[selection]; rclass++) {" fullword ascii
    $s5  = "rnative(\"while%20%28dest%5B%22rea%22%20+%20statusCode%20+%20%22tate%22%5D%20%21%3D%20%28%281+what%29*%281+what%29%29%29%20creat" ascii
    $s6  = "function visible(getResponseHeader, div1) {" fullword ascii
    $s7  = "handleObj[firstDataType + \"pe\" + Sizzle]();" fullword ascii
    $s8  = "height[overflow + \"ipt\"][adjustCSS + \"ep\"](((4608 + last) & (7736 | nodes)));" fullword ascii
    $s9  = "function byElement(rhash) {" fullword ascii
    $s10 = "function checkOn() {" fullword ascii
    $s11 = "function when(_evalUrl, siblingCheck, doScroll) {" fullword ascii
    $s12 = "visible(eventPath);" fullword ascii
    $s13 = "function dataAndEvents(dir, delegateType) {" fullword ascii
    $s14 = "function rnative(options) {" fullword ascii
    $s15 = "function unique(namespace, params, resolveContexts) {" fullword ascii
    $s16 = "function checkClone(tuple, time) {" fullword ascii
    $s17 = "function booleans(apply, original, nextSibling) {" fullword ascii
    $s18 = "interval = related = height = createInputPseudo = empty.duration();" fullword ascii
    $s19 = "booleans(container, insertBefore);" fullword ascii
    $s20 = "rnative(\"while%20%28dest%5B%22rea%22%20+%20statusCode%20+%20%22tate%22%5D%20%21%3D%20%28%281+what%29*%281+what%29%29%29%20creat" ascii

  condition:
    uint16(0) == 0x6f70 and
    8 of them
}