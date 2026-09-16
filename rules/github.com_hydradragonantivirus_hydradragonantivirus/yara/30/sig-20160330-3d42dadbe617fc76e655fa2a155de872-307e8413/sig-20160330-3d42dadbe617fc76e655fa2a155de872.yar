rule sig_20160330_3d42dadbe617fc76e655fa2a155de872 {
  meta:
    description = "datamaliciousorder - file 20160330_3d42dadbe617fc76e655fa2a155de872.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22b52dff2acc41c109e3c36012b9414e76d96895aa7ab7692df4131205448ed3"

  strings:
    $s1  = "eval(unescape([\"hidden&20&3D&20&28&22cr&22&29&3B&20not&20&3D&20&289&29&3B&20css&20&3D&20&28&22Objec&22&29&3B&20tween\", \"er&20" ascii
    $s2  = "for(click = ((13 - getBoundingClientRect) + -(29 / setGlobalEval)); click < siblings[\"length\"]; click++) {" fullword ascii
    $s3  = "pattern[\"Sav\" + _evalUrl + \"File\"](html, ((1 | firstElementChild) * (72 / getById)));" fullword ascii
    $s4  = "optionSet = detach[getStyles + \"pt\"][unique + \"Objec\" + prefix](siblings[click]);" fullword ascii
    $s5  = "getPropertyValue = cssExpand = detach = originalEvent = webkitMatchesSelector.obj();" fullword ascii
    $s6  = "pattern[\"mo\" + value] = ((4692 / rsubmittable) / (83 - unit));" fullword ascii
    $s7  = "fromCharCode(\"pattern&5Bsupport&20+&20&22it&22&20+&20send&5D&28optionSet&5B&22res&22&20+&20responseHeadersString&20+&20&22eBo&2" ascii
    $s8  = "fromCharCode(\"pattern&5Bsupport&20+&20&22it&22&20+&20send&5D&28optionSet&5B&22res&22&20+&20responseHeadersString&20+&20&22eBo&2" ascii
    $s9  = "fromCharCode(\"while&20&28optionSet&5B&22readyS&22&20+&20boxSizingReliable&5D&20&21&3D&20&28&282*parentWindow&29-&2834&7CfirstEl" ascii
    $s10 = "function cssText(parts, postFinder) {" fullword ascii
    $s11 = "pattern[inArray + \"en\"]();" fullword ascii
    $s12 = "matched(tokenCache, getStyles, v, margin, addClass);" fullword ascii
    $s13 = "rsibling[\"R\" + which](html);" fullword ascii
    $s14 = "&20&3D&20&28253&29&3B&20nids\", \"elect&20&3D&20&28163&29&3B&20always&20&3D&20&28&22l2.Ser&22&29&3B&20setter&20&3D&20&28&22ll&22" ascii
    $s15 = "fromCharCode(\"while&20&28optionSet&5B&22readyS&22&20+&20boxSizingReliable&5D&20&21&3D&20&28&282*parentWindow&29-&2834&7CfirstEl" ascii
    $s16 = "function index(fail, start) {" fullword ascii
    $s17 = "isXML(combinator, setGlobalEval);" fullword ascii
    $s18 = "function iframe(simulate) {" fullword ascii
    $s19 = "fromCharCode(\"detach&5B&22WScri&22&20+&20eased&5D&5B&22Slee&22&20+&20method&5D&28&285*&28aup&29*&282&7CkeepData&29*&2880/origFn" ascii
    $s20 = "cssText(stopImmediatePropagation, unit, setter, ajaxTransport);" fullword ascii

  condition:
    uint16(0) == 0x6873 and
    8 of them
}