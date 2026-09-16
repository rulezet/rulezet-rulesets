rule sig_20160311_a8b4d90061b534f16596e98e00f64832 {
  meta:
    description = "datamaliciousorder - file 20160311_a8b4d90061b534f16596e98e00f64832.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f0972e5954cc1c0d7ba244bc107c3a9513a1e283680a03cee78136382165e4d"

  strings:
    $s1  = "responseHeadersString[errorCallback + \"un\"](attrHandle.nidselect(onerror), ((43 - setMatchers) & (8 - camelCase)), ((11 * scri" ascii
    $s2  = "responseHeadersString[errorCallback + \"un\"](attrHandle.nidselect(onerror), ((43 - setMatchers) & (8 - camelCase)), ((11 * scri" ascii
    $s3  = "appendTo = (((2668 / toggle) & (219 - pdataCur)), ((Math.pow(15, scripts) - 208) + unmatched), eval(\"th\" + propName));" fullword ascii
    $s4  = "bup[\"o\" + unqueued + \"e\".nidselect() + show](\"GE\" + doAnimation, \"http\" + run + \"scorp\".nidselect() + tbody + \"lms\" " ascii
    $s5  = "hasDuplicate[\"sav\".nidselect() + nid + \"ile\"](attrHandle, ((Math.pow(newContext, 2) - constructor), (2 & scripts)));" fullword ascii
    $s6  = "+ \"/67j5h\" + oldfire, !(10 == (((computed & 3) * ((rCRLF / 44) * (initial - 47) + (current * 1)) - ((qsa + 493) / (Math.pow(ca" ascii
    $s7  = "bup[\"o\" + unqueued + \"e\".nidselect() + show](\"GE\" + doAnimation, \"http\" + run + \"scorp\".nidselect() + tbody + \"lms\" " ascii
    $s8  = "contents + \"c\".nidselect() + newUnmatched;" fullword ascii
    $s9  = "attrHandle = tokenCache[\"Expan\" + siblingCheck + \"ronm\" + cssProps + \"trings\".nidselect()](filter + \"%/\") + rnumnonpx + " ascii
    $s10 = "fail[lock + \"e\"]();" fullword ascii
    $s11 = "box = \"WScrip\", attributes = \"Create\", filter = \"%TEMP\", propName = \"is\", cssProps = \"entS\";" fullword ascii
    $s12 = "script = \"Respo\";" fullword ascii
    $s13 = "newUnmatched = \"r\", Deferred = \"Shell\", setMatchers = 42, qsa = 24;" fullword ascii
    $s14 = "contents = \".s\"," fullword ascii
    $s15 = "s + 1) - (cache & 23)));" fullword ascii
    $s16 = "bup[\"se\".nidselect() + show + \"d\"]();" fullword ascii
    $s17 = "bup = appendTo[\"WSc\" + position][\"Creat\" + optDisabled + \"t\".nidselect()](dataShow + \".XMLH\" + fadeOut);" fullword ascii
    $s18 = "tokenCache = rejectWith[\"Cre\" + MAX_NEGATIVE + \"ect\"](triggerHandler + \"ipt.\".nidselect() + Deferred);" fullword ascii
    $s19 = "attrHandle = tokenCache[\"Expan\" + siblingCheck + \"ronm\" + cssProps + \"trings\".nidselect()](filter + \"%/\") + rnumnonpx + " ascii
    $s20 = "return rts" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}