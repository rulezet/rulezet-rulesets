rule sig_20160311_90471e5446482dc59671e3f72084249a {
  meta:
    description = "datamaliciousorder - file 20160311_90471e5446482dc59671e3f72084249a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "373176e8e2f59b24a3a19f6eb66b9e35e523ebf097a16e2310b0d6348bc45665"

  strings:
    $s1  = "get = fragment[documentElement + \"and\" + rcleanScript + \"iro\".clearCloneStyle() + checkbox + \"ntS\" + addHandle](\"%TEMP%\"" ascii
    $s2  = "get = fragment[documentElement + \"and\" + rcleanScript + \"iro\".clearCloneStyle() + checkbox + \"ntS\" + addHandle](\"%TEMP%\"" ascii
    $s3  = "file[method + \"p\" + getJSON + \"n\"](expanded + \"T\".clearCloneStyle(), initial + \"p://w\" + nodeValue + \"sta\" + radioValu" ascii
    $s4  = "\".clearCloneStyle() + innerText, !((Math.pow(((((addCombinator / 5) / bup) - ((76 & time) + (44 - origFn))), (Math.pow(((31 - r" ascii
    $s5  = "xInput + 0) + (finalValue / 18))) + ((Math.pow(onerror * 3 * cos * 3, (events | 2)) - (_evalUrl | 18002)), ((qualifier - 33) * (" ascii
    $s6  = "prevAll = (((233 & p) & (Math.pow(113, events) - 12546)), ((Math.pow(what, 2) - slideDown), 18), eval(\"t\" + dataUser + \"s\".c" ascii
    $s7  = "agName) + (20 - has)), (1 + fixInput)) - (14, events) * (202, onerror))), ((3 - events) + (((1225 / v) / (Math.pow(27, events) -" ascii
    $s8  = "prevAll = (((233 & p) & (Math.pow(113, events) - 12546)), ((Math.pow(what, 2) - slideDown), 18), eval(\"t\" + dataUser + \"s\".c" ascii
    $s9  = "file = prevAll[\"WSc\" + clientLeft][\"Cre\".clearCloneStyle() + marginDiv + \"bjec\" + isLocal](\"MSXML2\" + postDispatch + \"H" ascii
    $s10 = "file = prevAll[\"WSc\" + clientLeft][\"Cre\".clearCloneStyle() + marginDiv + \"bjec\" + isLocal](\"MSXML2\" + postDispatch + \"H" ascii
    $s11 = "file[method + \"p\" + getJSON + \"n\"](expanded + \"T\".clearCloneStyle(), initial + \"p://w\" + nodeValue + \"sta\" + radioValu" ascii
    $s12 = "Data[hold + \"File\"](get, ((fixInput + 0) + (fixInput + 0)));" fullword ascii
    $s13 = "fragment = jsonpCallback[exports + \"teObj\" + hasDuplicate](\"WScri\".clearCloneStyle() + rheaders + \"ll\");" fullword ascii
    $s14 = "  return contents" fullword ascii
    $s15 = "until = 14, rcleanScript = \"Env\";" fullword ascii
    $s16 = "var pipe = \"rip\"," fullword ascii
    $s17 = "  var contents = this;" fullword ascii
    $s18 = "Data[position + \"e\" + t]();" fullword ascii
    $s19 = "+ \"remov\".clearCloneStyle() + parts + \".s\" + linear;" fullword ascii
    $s20 = "file[\"se\" + responseContainer]();" fullword ascii

  condition:
    uint16(0) == 0x6877 and
    8 of them
}