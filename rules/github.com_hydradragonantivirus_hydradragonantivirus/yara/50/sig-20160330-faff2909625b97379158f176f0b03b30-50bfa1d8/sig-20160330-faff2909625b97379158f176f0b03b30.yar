rule sig_20160330_faff2909625b97379158f176f0b03b30 {
  meta:
    description = "datamaliciousorder - file 20160330_faff2909625b97379158f176f0b03b30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8164375f21d959ac7315e17e02557b84c8b46a97ab83bde5147d42471389119"

  strings:
    $x1  = "eval(unescape([\"var&20boxSizingReliable&20&3D&20&28&22en&22&29&2C&20cssExpand&20&3D&20&28&22verX&22&29&2C&20boolHook\", \"&20&3" ascii
    $s2  = "   backgroundClip(\"implementation&20&3D&20&5B&22Msxml&22&20+&20beforeunload&20+&20&22verXM&22&20+&20tr&20+&20&22.6.0&22&2C&20da" ascii
    $s3  = "   backgroundClip(\"while&20&28stopQueue&5BrscriptTypeMasked&20+&20&22Stat&22&20+&20off&5D&20&21&3D&20&28Math.pow&28&28test+1&29" ascii
    $s4  = "init(tr, nextUntil, boxSizingReliable, camelKey, operator);" fullword ascii
    $s5  = "options[stateVal + \"pe\"] = ((1 | qsa) + (0 | initial));" fullword ascii
    $s6  = "   for (conv2 = ((17 / headers) * (1 & initial)); conv2 < implementation[\"le\" + jsonProp + \"h\"]; conv2++) {" fullword ascii
    $s7  = "checked = pdataCur = updateFunc = ajaxSetup = string.bind();" fullword ascii
    $s8  = "function pseudos(readyWait, iterator) {" fullword ascii
    $s9  = "2C&20mapped&20&3D&20&28&22St\", \"ream&22&29&2C&20qsa&20&3D&20&281&29&2C&20condense&20&3D&20&283&29&3Btr&20&3D&20&28&22LHTTP&22&" ascii
    $s10 = "3D&20&28&22puBQO&22&29&2C&20newCache&20&3D&20&28253&29&2C&20\", \"operator&20&3D&20&28&22Msxml&22&29&2C&20newSelector&20&3D&20&2" ascii
    $s11 = "function rtypenamespace() {" fullword ascii
    $s12 = "function preDispatch() {" fullword ascii
    $s13 = "function parse(setPositiveNumber) {" fullword ascii
    $s14 = "function rcssNum(ontype) {" fullword ascii
    $s15 = "function rnative(ajaxExtend) {" fullword ascii
    $s16 = "   backgroundClip(\"while&20&28stopQueue&5BrscriptTypeMasked&20+&20&22Stat&22&20+&20off&5D&20&21&3D&20&28Math.pow&28&28test+1&29" ascii
    $s17 = "parse(argument, initial, timeStamp, qsa);" fullword ascii
    $s18 = "function propFilter(option) {" fullword ascii
    $s19 = "16-top&29*&283+test&29*&281*test&29*&2860-href&29&29&29&3B\".replace(/&/g, '%'));" fullword ascii
    $s20 = "function clientY(defer, responses) {" fullword ascii

  condition:
    uint16(0) == 0x6461 and
    1 of ($x*) and 4 of them
}