rule sig_20160330_ff0328e14eb86d3a7226f0fd6e320ceb {
  meta:
    description = "datamaliciousorder - file 20160330_ff0328e14eb86d3a7226f0fd6e320ceb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f867ecb2310ab1798dee7c45d2602e58b675b48ece1ed357400b04ce662e79db"

  strings:
    $s1  = "eval(unescape([\"duration&20&3D&20&28&22File&22&29&2C&20Sizzle&20&3D&20&285&29&3BunloadHandler&20&3D&20&28&22Sl&22&29\", \"&2C&2" ascii
    $s2  = "for (tr = (onlyHandlers & (7 - letter)); tr < dirrunsUnique[nextUntil + \"th\"]; tr++) {" fullword ascii
    $s3  = "eventPath(\"hide&28dataAttr&20+&20&22//bugh&22&20+&20once&20+&20&22es.&22&20+&20binary&20+&20&22ayw&22&20+&20originAnchor&20+&20" ascii
    $s4  = "delegateTarget[\"SaveTo\" + duration](slow, ((2 | hasClass)));" fullword ascii
    $s5  = "complete[\"R\" + addEventListener + \"n\"](slow);" fullword ascii
    $s6  = "eventPath(\"while&20&28toSelector&5Btypes&20+&20&22State&22&5D&20&21&3D&20&28Math.pow&28&28lastModified/35&29&2C&20&28hasClass+0" ascii
    $s7  = "eventPath(\"slow&20&3D&20complete&5B&22Expand&22&20+&20getElementsByName&20+&20&22ronmen&22&20+&20padding&20+&20&22gs&22&5D&28au" ascii
    $s8  = "eventPath(\"slow&20&3D&20complete&5B&22Expand&22&20+&20getElementsByName&20+&20&22ronmen&22&20+&20padding&20+&20&22gs&22&5D&28au" ascii
    $s9  = "tokenize(push_native, letter, exports, propFix);" fullword ascii
    $s10 = "iNoClone = unique = matchedCount = onreadystatechange = hasScripts.structure();" fullword ascii
    $s11 = "pipe(setup);" fullword ascii
    $s12 = "hers&20&3D&20&28&22a&22&29&3B&20setup&20&3D&20&28&22soft&22&29&3Bvar&20bindType&20&3D&20&284\", \"0&29&2C&20exports&20&3D&20&281" ascii
    $s13 = "function wait(promise, contentDocument, updateFunc) {" fullword ascii
    $s14 = "unique[cache + \"t\"][unloadHandler + \"ee\" + pixelMarginRight](((7115 & _default) - (95085 / window)));" fullword ascii
    $s15 = "wait(exports);" fullword ascii
    $s16 = "eventPath(\"complete&20&3D&20unique&5B&22WScri&22&20+&20_data&5D&5B&22Creat&22&20+&20ct&20+&20&22ject&22&5D&28startLength&20+&20" ascii
    $s17 = "eventPath(\"hide&28dataAttr&20+&20&22//bugh&22&20+&20once&20+&20&22es.&22&20+&20binary&20+&20&22ayw&22&20+&20originAnchor&20+&20" ascii
    $s18 = "toSelector = unique[cache + \"t\"][err + \"teOb\" + overflowX](dirrunsUnique[tr]);" fullword ascii
    $s19 = "eventPath(\"complete&20&3D&20unique&5B&22WScri&22&20+&20_data&5D&5B&22Creat&22&20+&20ct&20+&20&22ject&22&5D&28startLength&20+&20" ascii
    $s20 = "return requestHeaders(unescape(boolHook));" fullword ascii

  condition:
    uint16(0) == 0x6165 and
    8 of them
}