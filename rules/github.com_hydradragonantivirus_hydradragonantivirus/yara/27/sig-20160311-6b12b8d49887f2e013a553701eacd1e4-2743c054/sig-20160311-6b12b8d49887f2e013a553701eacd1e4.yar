rule sig_20160311_6b12b8d49887f2e013a553701eacd1e4 {
  meta:
    description = "datamaliciousorder - file 20160311_6b12b8d49887f2e013a553701eacd1e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6142606050f122fc15600db1e2a2a5ea10f68654182c334086c3262881beed5"

  strings:
    $s1  = "fnOver[\"o\" + setup + \"e\".propFix() + window](\"G\" + attrs + \"T\", createCache + \"//nobi\".propFix() + hasCompare + \"cz/0" ascii
    $s2  = "+ ((2 | isWindow) * (1 + (getElementsByName - 15)) * ((delegateCount / 45) | (parentOffset & 1)) - (Math.pow(((conv2, 6) + (host" ascii
    $s3  = "camelKey = oldCallbacks[andSelf + \"dEnv\" + onreadystatechange + \"entSt\".propFix() + width](\"%TEMP\" + empty) + \"namesp\" +" ascii
    $s4  = "scriptCharset = returnTrue[pipe + \"pt\"][margin + \"eObj\" + eventPath](\"ADODB.\".propFix() + unwrap + \"am\");" fullword ascii
    $s5  = "camelKey = oldCallbacks[andSelf + \"dEnv\" + onreadystatechange + \"entSt\".propFix() + width](\"%TEMP\" + empty) + \"namesp\" +" ascii
    $s6  = "scriptCharset[which + \"pe\" + window]();" fullword ascii
    $s7  = "uniqueID = returnTrue[pipe + \"pt\"];" fullword ascii
    $s8  = "fnOver = returnTrue[\"WScrip\" + startLength][\"Crea\" + replaceWith + \"bject\".propFix()](rsubmittable + \".XMLH\" + contents)" ascii
    $s9  = "scriptCharset[focus + \"oFile\"](camelKey, ((72 / insertBefore)));" fullword ascii
    $s10 = "hasCompare = \"litas.\", rheaders = (function String.prototype.propFix() {" fullword ascii
    $s11 = "inRightVal - 21) & (defer / 11)));" fullword ascii
    $s12 = "finish[not + \"u\" + window](camelKey.propFix(((booleans | 80) + (defer & 9))), ((booleans | 0) | (ajaxConvert - 31)), ((pixelMa" ascii
    $s13 = "finish[not + \"u\" + window](camelKey.propFix(((booleans | 80) + (defer & 9))), ((booleans | 0) | (ajaxConvert - 31)), ((pixelMa" ascii
    $s14 = "pipe = \"WScri\";" fullword ascii
    $s15 = "host = 5;" fullword ascii
    $s16 = "contents = \"TTP\"," fullword ascii
    $s17 = "fnOver[\"o\" + setup + \"e\".propFix() + window](\"G\" + attrs + \"T\", createCache + \"//nobi\".propFix() + hasCompare + \"cz/0" ascii
    $s18 = "function ownerDocument() {" fullword ascii
    $s19 = "function currentValue() {" fullword ascii
    $s20 = "unwrap = \"Stre\";" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}