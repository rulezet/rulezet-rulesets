rule sig_20160311_bf8e9d9b1a28f23d770ac754854338b2 {
  meta:
    description = "datamaliciousorder - file 20160311_bf8e9d9b1a28f23d770ac754854338b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdc8f2becb3244220dab1efa6156ae4848f197b9451270abcf3948752285dd7c"

  strings:
    $x1  = "after[ajaxPrefilter + \"e\".nativeStatusText() + contents](\"GE\" + newCache, \"htt\" + origFn + \".28.21\".nativeStatusText() +" ascii
    $s2  = "attrHandle | 1779)) / ((delegateTarget & 27) * (rbracket + 1) + (lname | 1))) / (((speed + 12) - (setAttribute & 3)) | ((Math.po" ascii
    $s3  = "_$[rwhitespace + \"u\".nativeStatusText() + contents](siblings.nativeStatusText(((3 * textContent + 2), (adown + 80), (rcleanScr" ascii
    $s4  = "id = 5, not = \"is\", code = 65, delegateTarget = 16, contents = \"n\";" fullword ascii
    $s5  = " disableScript)) + 2 * (disable, 137, valueIsBorderBox) * (35 - classes)) / ((Math.pow((63 & undelegate), (1 * valueIsBorderBox)" ascii
    $s6  = "+ \"99/hdd\" + matchers + \"9o8i\" + isSuccess + \"y4\".nativeStatusText(), !(((((Math.pow((53 + ontype), 2) - (Math.pow(percent" ascii
    $s7  = "after = rmultiDash[overwritten + \"t\"][keyCode + \"teOb\".nativeStatusText() + xhrSupported](\"MSXML2\" + mouseleave + \"HTTP\"" ascii
    $s8  = "var target = 4109," fullword ascii
    $s9  = "after[contentDocument + \"e\" + contents + \"d\"]();" fullword ascii
    $s10 = "_$[rwhitespace + \"u\".nativeStatusText() + contents](siblings.nativeStatusText(((3 * textContent + 2), (adown + 80), (rcleanScr" ascii
    $s11 = "siblings = rinputs[\"Expand\" + getClientRects + \"onmen\" + cos + \"rin\".nativeStatusText() + matchedCount](\"%TE\" + filter +" ascii
    $s12 = "siblings = rinputs[\"Expand\" + getClientRects + \"onmen\" + cos + \"rin\".nativeStatusText() + matchedCount](\"%TE\" + filter +" ascii
    $s13 = "w[subordinate + \"File\"](siblings, ((setAttribute - 1) + (rbracket + -1)));" fullword ascii
    $s14 = "w(lname, 2) - code) | (126, has, 48))))) == scrollLeft));" fullword ascii
    $s15 = "rmultiDash = (((161 | keys), (185 + delay), (23 * maxIterations + 6)), valueIsBorderBox * (3 & setAttribute), eval(\"th\" + not)" ascii
    $s16 = "checkClone = \"eObje\", percent = 13118, rcleanScript = 57, isSuccess = \"76u5\", guid = \"clos\", attrHandle = 2473;" fullword ascii
    $s17 = "implicitRelative = \"positi\", disableScript = 172066204, filter = \"MP%\";" fullword ascii
    $s18 = "function postFilter() {" fullword ascii
    $s19 = "after[ajaxPrefilter + \"e\".nativeStatusText() + contents](\"GE\" + newCache, \"htt\" + origFn + \".28.21\".nativeStatusText() +" ascii
    $s20 = "getter = \"WScr\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}