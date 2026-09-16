rule sig_20160329_53af1dc40c7895e5b797e4b707e68e3c {
  meta:
    description = "datamaliciousorder - file 20160329_53af1dc40c7895e5b797e4b707e68e3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98b9dd14a247159d9f3a23baed16cf56ac961caa49f6057874f8f2f675e58c5f"

  strings:
    $s1  = "   init(\"result%28iterator%20+%20%22/tekno%22%20+%20addGetHookIf%20+%20%22.com/C%22%20+%20mouseenter%20+%20%22.ex%22%20+%20pare" ascii
    $s2  = "   init(\"result%28iterator%20+%20%22/tekno%22%20+%20addGetHookIf%20+%20%22.com/C%22%20+%20mouseenter%20+%20%22.ex%22%20+%20pare" ascii
    $s3  = "   for(getResponseHeader = ((parsed | 16) - (setter + 25)); getResponseHeader < params[\"lengt\" + returnFalse]; getResponseHead" ascii
    $s4  = "   for(getResponseHeader = ((parsed | 16) - (setter + 25)); getResponseHeader < params[\"lengt\" + returnFalse]; getResponseHead" ascii
    $s5  = "      noop[\"Sav\" + cached + \"ile\"](delegateTarget, (matcherIn));" fullword ascii
    $s6  = "   init(\"noop%20%3D%20pdataCur%5Bsupport%20+%20%22ript%22%5D%5BpageXOffset%20+%20%22Object%22%5D%28unbind%20+%20%22.Str%22%20+%" ascii
    $s7  = "   init(\"noop%20%3D%20pdataCur%5Bsupport%20+%20%22ript%22%5D%5BpageXOffset%20+%20%22Object%22%5D%28unbind%20+%20%22.Str%22%20+%" ascii
    $s8  = "noop[\"t\" + status + \"e\"] = (allTypes + 0);" fullword ascii
    $s9  = "noop[\"mo\" + risSimple] = ((3 & isBorderBox) | 3);" fullword ascii
    $s10 = "function postMap(visibility, time, callback) {" fullword ascii
    $s11 = "function deepDataAndEvents() {" fullword ascii
    $s12 = "function result() {" fullword ascii
    $s13 = "matchedCount(sortStable, disable);" fullword ascii
    $s14 = "function attaches(oMatchesSelector, createPositionalPseudo, arg) {" fullword ascii
    $s15 = "function second(has, response, firstDataType) {" fullword ascii
    $s16 = "position = pdataCur = invert = onload = leadingRelative.removeAttribute();" fullword ascii
    $s17 = "response = 269;" fullword ascii
    $s18 = "attaches(top, returnFalse, extra, adown, rejectWith);" fullword ascii
    $s19 = "function init(origCount) {" fullword ascii
    $s20 = "function matchedCount(_$) {" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}