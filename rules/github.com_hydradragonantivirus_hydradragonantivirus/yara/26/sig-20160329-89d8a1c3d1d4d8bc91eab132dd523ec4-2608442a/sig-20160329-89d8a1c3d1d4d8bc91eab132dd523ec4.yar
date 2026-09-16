rule sig_20160329_89d8a1c3d1d4d8bc91eab132dd523ec4 {
  meta:
    description = "datamaliciousorder - file 20160329_89d8a1c3d1d4d8bc91eab132dd523ec4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3eb69f37ea726880ee19cf55a0db00782d6906061cd0cb066709815c6d48dc36"

  strings:
    $s1  = "radioValue(\"while%20%28cloneCopyEvent%5B%22read%22%20+%20createInputPseudo%20+%20%22e%22%5D%20%21%3D%20%28%28100/elem%29*%2827-" ascii
    $s2  = "sortDetached[file + \"p\" + scale] = ((37 / extra) * (26 - rheader));" fullword ascii
    $s3  = "header%29%29%29%20vendorPropName%5Brnamespace%20+%20%22t%22%5D%5Brparentsprev%5D%28%28%285*keys*2*sibling%29%26%28108%7CnewConte" ascii
    $s4  = "sortDetached[timerId + \"de\"] = ((1 & defaultPrefilter) * (16 - prefix));" fullword ascii
    $s5  = "for (protocol = (1 * ontype); protocol < bySet[\"len\" + support]; protocol++) {" fullword ascii
    $s6  = "sortDetached[\"SaveT\" + setMatched](arr, ((40 / swing) | (144, ontype)));" fullword ascii
    $s7  = "string[progressContexts + \"un\"](arr);" fullword ascii
    $s8  = "cloneCopyEvent = vendorPropName[\"WSc\" + show][\"Creat\" + pageY + \"ct\"](bySet[protocol]);" fullword ascii
    $s9  = "if (cloneCopyEvent[\"sta\" + parse] == ((140 & charset), (202 & marginLeft))) {" fullword ascii
    $s10 = "radioValue(\"while%20%28cloneCopyEvent%5B%22read%22%20+%20createInputPseudo%20+%20%22e%22%5D%20%21%3D%20%28%28100/elem%29*%2827-" ascii
    $s11 = "th(bind, prev, dataShow, file, now);" fullword ascii
    $s12 = "function th() {" fullword ascii
    $s13 = "function selected() {" fullword ascii
    $s14 = "function attr() {" fullword ascii
    $s15 = "function acceptData(destElements, attrId, createElement) {" fullword ascii
    $s16 = "acceptData(splice, lname);" fullword ascii
    $s17 = "function radioValue(responses) {" fullword ascii
    $s18 = "function eventDoc(appendChild, nodeNameSelector, timeoutTimer) {" fullword ascii
    $s19 = "function random(xhrSuccessStatus) {" fullword ascii
    $s20 = "cloneCopyEvent[\"s\" + scale + \"n\" + parts]();" fullword ascii

  condition:
    uint16(0) == 0x6174 and
    8 of them
}