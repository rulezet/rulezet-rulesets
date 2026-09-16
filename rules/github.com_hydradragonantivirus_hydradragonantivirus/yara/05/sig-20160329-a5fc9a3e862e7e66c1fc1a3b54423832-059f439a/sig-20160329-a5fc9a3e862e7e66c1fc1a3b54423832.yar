rule sig_20160329_a5fc9a3e862e7e66c1fc1a3b54423832 {
  meta:
    description = "datamaliciousorder - file 20160329_a5fc9a3e862e7e66c1fc1a3b54423832.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a810629ec69b9944369d7700f0a96cb8cff5e55453ea15b4be1b1668126818b6"

  strings:
    $s1  = "0%22oro%22%20+%20overflowY%20+%20%22.com/9%22%20+%20sortInput%20+%20%22TP.exe%22%2C%20%21%28%28%28index-35%29/%28global*3*global" ascii
    $s2  = "init(\"rmouseEvent%5BgenFx%20+%20%22e%22%20+%20originalEvent%5D%28%22GE%22%20+%20identifier%2C%20%22htt%22%20+%20outerCache%20+%" ascii
    $s3  = "function _queueHooks(temp, strAbort, leadingRelative) {" fullword ascii
    $s4  = "rmouseEvent = contains[compareDocumentPosition + \"pt\"][doc + \"Object\"](memory[outermostContext]);" fullword ascii
    $s5  = "init(\"memory%20%3D%20%5BandSelf%20+%20%22.Serv%22%20+%20string%20+%20%22LHT%22%20+%20pop%2C%20%22Msxml%22%20+%20emptyGet%20+%20" ascii
    $s6  = "init(\"while%20%28rmouseEvent%5B%22read%22%20+%20nextUntil%5D%20%21%3D%20%28%28113+sort%29/%28125%2CcapName%2C225%2CcurCSS%29%29" ascii
    $s7  = "getJSON(string, timers);" fullword ascii
    $s8  = "init(\"memory%20%3D%20%5BandSelf%20+%20%22.Serv%22%20+%20string%20+%20%22LHT%22%20+%20pop%2C%20%22Msxml%22%20+%20emptyGet%20+%20" ascii
    $s9  = "xhr[\"SaveT\" + extend](nativeStatusText, (global | 0));" fullword ascii
    $s10 = "for(outermostContext = ((speed, 0) | (webkitMatchesSelector & 0)); outermostContext < memory[\"le\" + cloneNode + \"th\"]; outer" ascii
    $s11 = "for(outermostContext = ((speed, 0) | (webkitMatchesSelector & 0)); outermostContext < memory[\"le\" + cloneNode + \"th\"]; outer" ascii
    $s12 = "function rhash() {" fullword ascii
    $s13 = "fireWith(completeDeferred, speed, nidselect, timers);" fullword ascii
    $s14 = "function fireWith() {" fullword ascii
    $s15 = "function isWindow() {" fullword ascii
    $s16 = "function init(fns) {" fullword ascii
    $s17 = "removeChild(sort);" fullword ascii
    $s18 = "function ajax(mouseenter, name) {" fullword ascii
    $s19 = "function removeChild(stored) {" fullword ascii
    $s20 = "function wrapAll(firstChild, fadeIn) {" fullword ascii

  condition:
    uint16(0) == 0x6166 and
    8 of them
}