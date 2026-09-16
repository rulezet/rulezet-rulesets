rule sig_20160329_8f1ed5535fa103ca5eeaf850499fb39f {
  meta:
    description = "datamaliciousorder - file 20160329_8f1ed5535fa103ca5eeaf850499fb39f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a23c97588f3a3f4907e3a045e3bd038578542db2448b275d326065ce7604cbbd"

  strings:
    $s1  = "preDispatch(\"responseHeaders%20%3D%20%5BsortStable%20+%20%22ml2.%22%20+%20caption%20+%20%22erXML%22%20+%20flatOptions%20+%20%22" ascii
    $s2  = "for (id = ((1 + -progressValues) / (76 - fragment)); id < responseHeaders[clearQueue + \"n\" + originalProperties + \"h\"]; id++" ascii
    $s3  = "addEventListener[\"t\" + qualifier + \"e\"] = ((35 - assert) / (7 | rfxtypes));" fullword ascii
    $s4  = "preDispatch(\"checkbox%5B%22o%22%20+%20html%20+%20%22n%22%5D%28stopPropagation%20+%20%22ET%22%2C%20stop%20+%20%22%3A//s%22%20+%2" ascii
    $s5  = "requestHeaders(host, camelKey, progressContexts);" fullword ascii
    $s6  = "function letterSpacing(key, currentTime, scripts) {" fullword ascii
    $s7  = "checkbox = wait[val + \"t\"][dir + \"Obje\" + rts](responseHeaders[id]);" fullword ascii
    $s8  = "preDispatch(\"addEventListener%20%3D%20dest%5Bval%20+%20%22t%22%5D%5Bhost%20+%20%22ate%22%20+%20pattern%5D%28%22ADODB%22%20+%20m" ascii
    $s9  = "preDispatch(\"addEventListener%20%3D%20dest%5Bval%20+%20%22t%22%5D%5Bhost%20+%20%22ate%22%20+%20pattern%5D%28%22ADODB%22%20+%20m" ascii
    $s10 = "preDispatch(\"percent%28stop%20+%20%22%3A//s%22%20+%20matcher%20+%20%22albuil%22%20+%20timeout%20+%20%22m/jp9%22%20+%20dataAttr%" ascii
    $s11 = "if (checkbox[\"s\" + readyWait] == ((255 & fadeToggle) & (192 | context))) {" fullword ascii
    $s12 = "preDispatch(\"reliableMarginLeftVal%20%3D%20access%5BcamelKey%20+%20%22Env%22%20+%20contains%20+%20%22ntS%22%20+%20callbackInver" ascii
    $s13 = "preDispatch(\"access%20%3D%20wait%5B%22WScr%22%20+%20scrollTop%5D%5B%22Creat%22%20+%20hash%20+%20%22ect%22%5D%28combinator%20+%2" ascii
    $s14 = "preDispatch(\"access%20%3D%20wait%5B%22WScr%22%20+%20scrollTop%5D%5B%22Creat%22%20+%20hash%20+%20%22ect%22%5D%28combinator%20+%2" ascii
    $s15 = "function requestHeaders() {" fullword ascii
    $s16 = "text%2C204%2CrequestHeadersNames%29%29%29%3B\");" fullword ascii
    $s17 = "access[startTime + \"un\"](reliableMarginLeftVal);" fullword ascii
    $s18 = "checkbox[\"s\" + simple + \"d\"]();" fullword ascii
    $s19 = "function createPositionalPseudo(qsaError) {" fullword ascii
    $s20 = "preDispatch(\"addEventListener%5BattachEvent%20+%20%22od%22%20+%20defer%5D%20%3D%20%28%281*globalEval%29%7C%282+progressValues%2" ascii

  condition:
    uint16(0) == 0x6572 and
    8 of them
}