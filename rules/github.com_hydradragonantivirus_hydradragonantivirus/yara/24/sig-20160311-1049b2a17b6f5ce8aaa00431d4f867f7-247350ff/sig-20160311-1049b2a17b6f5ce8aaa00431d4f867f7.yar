rule sig_20160311_1049b2a17b6f5ce8aaa00431d4f867f7 {
  meta:
    description = "datamaliciousorder - file 20160311_1049b2a17b6f5ce8aaa00431d4f867f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8df68a892f75722da88f2634551d8adec138b7d34a1a4ad2b992c180ef1f6307"

  strings:
    $s1  = "key = next[\"WSc\" + computed][\"Cre\".offsetWidth() + rcheckableType + \"Obj\" + getAll](\"MSXML2\" + completeDeferred + \"HTTP" ascii
    $s2  = "key = next[\"WSc\" + computed][\"Cre\".offsetWidth() + rcheckableType + \"Obj\" + getAll](\"MSXML2\" + completeDeferred + \"HTTP" ascii
    $s3  = "key[defer + \"en\"](init + \"T\", check + \"://p\".offsetWidth() + checkOn + \"dickem\" + round + \"m/8\" + preventDefault + \"5" ascii
    $s4  = "conditionFn = \"%TEM\", init = \"GE\", xhrSupported = 21, bind = 63, responseContainer = \"Create\", getAll = \"ect\";" fullword ascii
    $s5  = "astChild), (1 + triggerHandler)) - (246 + end)) | ((59 & bind) * 2 + (compiled + 6))) / (((rnamespace & 11), (preferredDoc | 48)" ascii
    $s6  = "configurable[animated + \"Fil\".offsetWidth() + parseXML](origType, ((48 & nidselect) - 46));" fullword ascii
    $s7  = "key[defer + \"en\"](init + \"T\", check + \"://p\".offsetWidth() + checkOn + \"dickem\" + round + \"m/8\" + preventDefault + \"5" ascii
    $s8  = "configurable[defer + \"e\".offsetWidth() + i]();" fullword ascii
    $s9  = "configurable = next[unwrap + \"ipt\"][responseContainer + \"Objec\".offsetWidth() + triggered](\"ADODB\" + memory + \"am\");" fullword ascii
    $s10 = "defer = \"op\", defaultValue = \"nseBod\", postMap = \"eep\", method = \"eOb\", triggerHandler = 1;" fullword ascii
    $s11 = "function postFilter() {" fullword ascii
    $s12 = "origType = styles[\"Expand\" + amd + \"ronme\" + curPosition + \"ings\".offsetWidth()](conditionFn + \"P%/\") + xhrSuccessStatus" ascii
    $s13 = "next = (((352 & fcamelCase) - (4636 / overflowX)), ((25, sort) & (242, load, 14)), eval(\"th\" + parseFromString));" fullword ascii
    $s14 = "actualDisplay = next[\"WScr\".offsetWidth() + hidden];" fullword ascii
    $s15 = "styles = actualDisplay[\"Creat\" + method + \"ject\"](siblings + \"t.Sh\".offsetWidth() + reverse);" fullword ascii
    $s16 = "var hidden = \"ipt\"," fullword ascii
    $s17 = " + opacity + \"nt\".offsetWidth() + prevUntil + \"sc\" + eq;" fullword ascii
    $s18 = "var compare = \"write\";" fullword ascii
    $s19 = " check = \"http\"," fullword ascii
    $s20 = "lastChild = 58, prevUntil = \".\", compiled = (function String.prototype.offsetWidth() {" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}