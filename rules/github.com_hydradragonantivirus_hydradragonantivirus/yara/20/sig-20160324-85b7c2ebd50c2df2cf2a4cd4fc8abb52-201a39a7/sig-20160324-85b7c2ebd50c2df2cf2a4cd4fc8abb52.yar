rule sig_20160324_85b7c2ebd50c2df2cf2a4cd4fc8abb52 {
  meta:
    description = "datamaliciousorder - file 20160324_85b7c2ebd50c2df2cf2a4cd4fc8abb52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22b498611a67717023ea0ca7d511d766312b605846f8f959f0d469e8ea63dbff"

  strings:
    $s1  = "defaultView[\"t\" + file + \"e\"] = ((9 - unbind) | 1);" fullword ascii
    $s2  = "deep[fireWith + \"ript\"][urlAnchor + \"e\" + pointerleave]((1 + serialize) * (48 - unit) * (Math.pow(3, errorCallback) - 4) * (" ascii
    $s3  = "deep[fireWith + \"ript\"][urlAnchor + \"e\" + pointerleave]((1 + serialize) * (48 - unit) * (Math.pow(3, errorCallback) - 4) * (" ascii
    $s4  = "detectDuplicates[\"Sleep\"](((Math.pow(reliableMarginLeftVal, 2) - Sizzle) / (36 | module)));" fullword ascii
    $s5  = "eval(elems(\"tween%28readyWait%20+%20%22seBo%22%20+%20isHidden%2C%20%28%28special*3%29%7C%28ap%2C24%2CxhrSupported%29%29%2C%20se" ascii
    $s6  = "eval(elems(\"tween%28readyWait%20+%20%22seBo%22%20+%20isHidden%2C%20%28%28special*3%29%7C%28ap%2C24%2CxhrSupported%29%29%2C%20se" ascii
    $s7  = "function elems(postDispatch) {" fullword ascii
    $s8  = "function getAll(finish, cssShow, oldfire, parentsUntil) {" fullword ascii
    $s9  = "ofType = what[capName + \"andEnv\" + copy + \"nme\" + current + \"trin\" + postFilter](\"%TE\" + firingIndex) + \"rmo\" + checkO" ascii
    $s10 = "postFilter = \"gs\", visibility = 19;" fullword ascii
    $s11 = "ofType = what[capName + \"andEnv\" + copy + \"nme\" + current + \"trin\" + postFilter](\"%TE\" + firingIndex) + \"rmo\" + checkO" ascii
    $s12 = "defaultView = new position[prevObject + \"veXObj\" + fadeToggle](\"ADO\" + matchedCount + \"ream\");" fullword ascii
    $s13 = "unbind = 8;" fullword ascii
    $s14 = "ial | 1) * errorCallback * 2 * (callbackExpect * 2) * special);" fullword ascii
    $s15 = "eval(elems(\"send%5Bmatches%20+%20%22tio%22%20+%20stopped%5D%20%3D%20%28%281363/responseText%29-%2845%7CxhrSupported%29%29%3B\")" ascii
    $s16 = "return unescape(postDispatch);" fullword ascii
    $s17 = "function gotoEnd() {" fullword ascii
    $s18 = "function method() {" fullword ascii
    $s19 = "function nextUntil() {" fullword ascii
    $s20 = "function structure() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}