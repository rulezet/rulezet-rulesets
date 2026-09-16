rule sig_20160330_749ed841129414185150d2158da89476 {
  meta:
    description = "datamaliciousorder - file 20160330_749ed841129414185150d2158da89476.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ffdb11afa9c984a5d618a106c89470189732336e57ee39a0f5431eb5b3123a3"

  strings:
    $s1  = "dirrunsUnique(\"document&5B&22o&22&20+&20statusText&20+&20&22e&22&20+&20genFx&5D&28&22G&22&20+&20rscriptType&2C&20&22http&3A/&22" ascii
    $s2  = "invert[\"WScri\" + getClientRects][\"Sleep\"]((Math.pow((5061 - dataType), 2) - (anim | 2097160)));" fullword ascii
    $s3  = "escapedWhitespace[chainable + \"yp\" + isSimulated] = ((48 | proxy) / (78 - getElementsByName));" fullword ascii
    $s4  = "dirrunsUnique(\"document&5B&22o&22&20+&20statusText&20+&20&22e&22&20+&20genFx&5D&28&22G&22&20+&20rscriptType&2C&20&22http&3A/&22" ascii
    $s5  = "return processData(unescape(setOffset));" fullword ascii
    $s6  = "submit(has, rcleanScript, delay, url);" fullword ascii
    $s7  = "dirrunsUnique(\"while&20&28document&5B&22ready&22&20+&20optDisabled&20+&20&22te&22&5D&20&21&3D&20&28&28computed+7&29/&28_removeD" ascii
    $s8  = "Script&20&3D&20&28&22eObje&22&29&2C&20has&20\", \"&3D&20&28function&20setGlobalEval&28&29&7B&7D&2C&2026&29&2C&20fix&20&3D&20&28f" ascii
    $s9  = "dirrunsUnique(\"while&20&28document&5B&22ready&22&20+&20optDisabled&20+&20&22te&22&5D&20&21&3D&20&28&28computed+7&29/&28_removeD" ascii
    $s10 = "function textContent(nodeValue, conv, linear) {" fullword ascii
    $s11 = "if(document[\"stat\" + concat] == ((384 - a) & (248 & events))) {" fullword ascii
    $s12 = "DOMParser[\"R\" + tuple](merge);" fullword ascii
    $s13 = "document = round[dataAttr + \"t\"][push_native + \"eObj\" + implicitRelative](jQuery[not]);" fullword ascii
    $s14 = "document[ajax + \"n\" + leadingRelative]();" fullword ascii
    $s15 = "function attrHandle(addToPrefiltersOrTransports, preMap) {" fullword ascii
    $s16 = "dirrunsUnique(\"merge&20&3D&20DOMParser&5B&22Expan&22&20+&20resolveContexts&20+&20&22ron&22&20+&20handlerQueue&20+&20&22String&2" ascii
    $s17 = "root = 666;" fullword ascii
    $s18 = "function dirrunsUnique(setOffset) {" fullword ascii
    $s19 = "dirrunsUnique(\"merge&20&3D&20DOMParser&5B&22Expan&22&20+&20resolveContexts&20+&20&22ron&22&20+&20handlerQueue&20+&20&22String&2" ascii
    $s20 = "function submit() {" fullword ascii

  condition:
    uint16(0) == 0x6f72 and
    8 of them
}