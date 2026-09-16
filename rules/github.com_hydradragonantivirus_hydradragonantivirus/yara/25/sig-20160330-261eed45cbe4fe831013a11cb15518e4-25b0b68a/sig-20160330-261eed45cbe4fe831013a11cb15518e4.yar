rule sig_20160330_261eed45cbe4fe831013a11cb15518e4 {
  meta:
    description = "datamaliciousorder - file 20160330_261eed45cbe4fe831013a11cb15518e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3f39fb38a433f1eabd78ffd6e124ae1425b212475b227ce20a5a4dc1739fbd6"

  strings:
    $x1  = "eval(unescape([\"marginDiv&20&3D&20&28&22tate&22&29&2C&20guid&20&3D&20&28&22P.3.0&22&29&2C&20attr&20&3D&20&28&22rver&\", \"22&29" ascii
    $s2  = "transport[inPage + \"pe\"] = (script - 48);" fullword ascii
    $s3  = "  if (matchers[\"stat\" + container] == (Math.pow((Math.pow(71, implementation) - 4908), (implementation | 2)) - (node * 29 + rd" ascii
    $s4  = "percent&20&3D&20&28&22l2.XML&22&29&3Brrun&20&3D&20&28function&20getAll.matchContext&28&29&7B\", \"var&20offsetHeight&3D&20&5B&5D" ascii
    $s5  = "  if (matchers[\"stat\" + container] == (Math.pow((Math.pow(71, implementation) - 4908), (implementation | 2)) - (node * 29 + rd" ascii
    $s6  = "      matchers = start[version + \"pt\"][notify + \"teObje\" + ready](optall[getElementsByName]);" fullword ascii
    $s7  = "  elemData(\"transport&20&3D&20duplicates&5Bsplit&20+&20&22ipt&22&5D&5Bconv2&20+&20&22Objec&22&20+&20contentType&5D&28&22ADOD&22" ascii
    $s8  = "transport[wait + \"de\"] = (1 + (implementation & 2));" fullword ascii
    $s9  = "  elemData(\"while&20&28matchers&5B&22readyS&22&20+&20marginDiv&5D&20&21&3D&20&28&28Math.pow&28isNumeric&2C&202&29-push&29&7C&28" ascii
    $s10 = "  elemData(\"while&20&28matchers&5B&22readyS&22&20+&20marginDiv&5D&20&21&3D&20&28&28Math.pow&28isNumeric&2C&202&29-push&29&7C&28" ascii
    $s11 = "collection(sortDetached, percent, isPropagationStopped, contentType, ajaxPrefilter);" fullword ascii
    $s12 = "  elemData(\"transport&20&3D&20duplicates&5Bsplit&20+&20&22ipt&22&5D&5Bconv2&20+&20&22Objec&22&20+&20contentType&5D&28&22ADOD&22" ascii
    $s13 = "    transport[clearCloneStyle + \"File\"](iNoClone, ((implementation & 3) | (emptyStyle, 0)));" fullword ascii
    $s14 = "    transport[\"o\" + what + \"n\"]();" fullword ascii
    $s15 = "namespaces = duplicates = nodeValue = start = getAll.matchContext();" fullword ascii
    $s16 = "function setDocument() {" fullword ascii
    $s17 = "function byElement() {" fullword ascii
    $s18 = "function collection() {" fullword ascii
    $s19 = "function dest(xhrSuccessStatus, curCSS) {" fullword ascii
    $s20 = "opQueue&20&3D&20&28&22ript&22&29&2C&20sel&20&3D&20&28&22P&22&29&2C&20ajaxPre\", \"filter&20&3D&20&28&22se&22&29&2C&20risSimple&2" ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}