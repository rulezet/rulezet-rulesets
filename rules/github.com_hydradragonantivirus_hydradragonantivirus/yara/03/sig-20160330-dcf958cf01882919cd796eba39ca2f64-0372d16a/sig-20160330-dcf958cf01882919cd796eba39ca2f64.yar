rule sig_20160330_dcf958cf01882919cd796eba39ca2f64 {
  meta:
    description = "datamaliciousorder - file 20160330_dcf958cf01882919cd796eba39ca2f64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b589c2ebea5162d84cac74219245b16d944491dc0863b624b21b3e4d3b470ab7"

  strings:
    $s1  = "   focus(\"requestHeadersNames&20&3D&20&5BcheckContext&20+&20&22l2.Ser&22&20+&20unquoted&20+&20&22XML&22&20+&20origFn&20+&20&22." ascii
    $s2  = "container[\"mo\" + tag + \"e\"] = ((4 - hasCompare) * (41 - doAnimation));" fullword ascii
    $s3  = "   for(when = ((complete * 2), (doAnimation - 38), (createElement * 2 * sortInput), (0 | opener)); when < requestHeadersNames[\"" ascii
    $s4  = "   for(when = ((complete * 2), (doAnimation - 38), (createElement * 2 * sortInput), (0 | opener)); when < requestHeadersNames[\"" ascii
    $s5  = "parseXML(unquoted, excess, textContent, keyHooks, guaranteedUnique);" fullword ascii
    $s6  = "innerText = related = fireWith = combinator = support.focusin();" fullword ascii
    $s7  = "function cssPrefixes(script, msg) {" fullword ascii
    $s8  = "   if(attaches[result] == ((Math.pow(1239, sortInput) - 1533121) / (runescape & 10))) {" fullword ascii
    $s9  = "function toggle(getWindow, promise, originalOptions) {" fullword ascii
    $s10 = "   focus(\"requestHeadersNames&20&3D&20&5BcheckContext&20+&20&22l2.Ser&22&20+&20unquoted&20+&20&22XML&22&20+&20origFn&20+&20&22." ascii
    $s11 = "   focus(\"attaches&5BstopImmediatePropagation&20+&20&22pe&22&20+&20finalText&5D&28&22G&22&20+&20progressContexts&2C&20&22htt&22" ascii
    $s12 = "function fail(whitespace, visible, preDispatch) {" fullword ascii
    $s13 = "function bind(matched) {" fullword ascii
    $s14 = "fail(propHooks);" fullword ascii
    $s15 = "      container[\"o\" + ready + \"e\" + finalText]();" fullword ascii
    $s16 = "blur&20&3D&20&28&22Creat&22&\", \"29&3B&20truncate&20&3D&20eval&3B&20createElement&20&3D&20&285&29&3B&20hasCompare&20&3D&20&283&" ascii
    $s17 = "function method() {" fullword ascii
    $s18 = "function input() {" fullword ascii
    $s19 = "function has() {" fullword ascii
    $s20 = "   focus(\"token&20&3D&20related&5B&22WScr&22&20+&20keyHooks&5D&5B&22Cre&22&20+&20preFilter&20+&20&22ject&22&5D&28cacheURL&20+&2" ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}