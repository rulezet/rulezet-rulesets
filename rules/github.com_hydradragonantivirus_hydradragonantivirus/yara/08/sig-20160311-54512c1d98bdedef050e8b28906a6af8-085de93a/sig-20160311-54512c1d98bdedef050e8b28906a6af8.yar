rule sig_20160311_54512c1d98bdedef050e8b28906a6af8 {
  meta:
    description = "datamaliciousorder - file 20160311_54512c1d98bdedef050e8b28906a6af8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a895a300693fd1c93446f16b40f5b4ebddd0880d47753e14a5002c69d78978d1"

  strings:
    $s1  = "globalEventContext[\"op\".results() + dirruns](\"G\" + oMatchesSelector, \"http:/\" + rprotocol + \"pyofi\".results() + username" ascii
    $s2  = "rsingleTag[\"R\".results() + tuple + \"n\"](contentDocument.results(((Math.pow(16, tr) - 227) * (check & 3) + (handleObj, 180, f" ascii
    $s3  = "rsingleTag[\"R\".results() + tuple + \"n\"](contentDocument.results(((Math.pow(16, tr) - 227) * (check & 3) + (handleObj, 180, f" ascii
    $s4  = "/ 2 * (postSelector * 2) * (simple / 31)), (Math.pow(((tr, 183, high, 292) - (structure - 169)), ((iNoClone, 136, tr) | (1 * max" ascii
    $s5  = "j\" + nextAll, !(((((1 + -postSelector) | (1 + maxWidth)) + ((1 & maxWidth) - (0 | maxWidth))) + ((227 * len * 2 / (load + 19))," ascii
    $s6  = "id[\"ty\".results() + radio + \"e\"] = ((1 + -postSelector) | (1 & postSelector));" fullword ascii
    $s7  = "contentDocument = implementation[clazz + \"Env\" + rclickable + \"entStr\".results() + valHooks](\"%TEMP\" + ignored) + \"do\" +" ascii
    $s8  = "contentDocument = implementation[clazz + \"Env\" + rclickable + \"entStr\".results() + valHooks](\"%TEMP\" + ignored) + \"do\" +" ascii
    $s9  = "(maxWidth / 17))) == ((((Math.pow((check * 3), (attr - 3)) - (origName & 85)) & (rjsonp & (237, elementMatcher, 112, load))) | (" ascii
    $s10 = "((1 * tr) + (1 * maxWidth)) | (Math.pow((2 + options), (199, tr)) - 54))) / ((((th | 12760) & (Math.pow(winnow, 2) - isHidden)) " ascii
    $s11 = "Width))) - ((4709 * check + 2533) | (reverse))), (Math.pow((6 - check), (2 & check)) - (2 * tr)) * (2 | maxWidth)))));" fullword ascii
    $s12 = "simulate[\"saveT\" + createTween + \"le\".results()](contentDocument, ((2 | tr) & (84 / ret)));" fullword ascii
    $s13 = "unmatched = ((10027 / run), (175 / attrId), eval(\"th\" + set + \"s\".results()));" fullword ascii
    $s14 = "onreadystatechange = unmatched[jsonProp + \"ript\"];" fullword ascii
    $s15 = "function operator() {" fullword ascii
    $s16 = "requestHeadersNames = simulate;" fullword ascii
    $s17 = "lname = \"clos\", structure = 327, postSelector = 1;" fullword ascii
    $s18 = "implementation = onreadystatechange[pageX + \"teObje\" + calculatePosition](\"WSc\".results() + rrun + \"Shell\");" fullword ascii
    $s19 = "operator();" fullword ascii
    $s20 = "simulate = unmatched[\"WSc\".results() + inspected][\"Cre\" + always + \"Objec\" + defineProperty](\"ADODB.\".results() + optDis" ascii

  condition:
    uint16(0) == 0x6163 and
    8 of them
}