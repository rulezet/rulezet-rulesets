rule sig_20160311_d9e958192f5a751353cb6bb8cf52a678 {
  meta:
    description = "datamaliciousorder - file 20160311_d9e958192f5a751353cb6bb8cf52a678.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "142354624e5474df7861b954288ad694f2fa0012880920c0d41802c6f7c46487"

  strings:
    $s1  = "els[\"op\" + src + \"n\"](doAnimation + \"ET\".memory(), scriptCharset + \"//nob\" + toSelector + \"s.cz\" + trim + \"4h45\".mem" ascii
    $s2  = "PI = ((1 + rnoInnerhtml) * (59 & content), ((5 & parentOffset) - (0 | classNames)), eval(\"th\" + dirruns + \"s\".memory()));" fullword ascii
    $s3  = "els[\"op\" + src + \"n\"](doAnimation + \"ET\".memory(), scriptCharset + \"//nob\" + toSelector + \"s.cz\" + trim + \"4h45\".mem" ascii
    $s4  = "laceWith - 2), (col / 13)) - (Math.pow($, 2) - cache))) | ((1536 / compiled * 2 * compiled * 2) - (Math.pow(compiled * 23, (noCo" ascii
    $s5  = "els = PI[contentDocument + \"ript\".memory()][count + \"teOb\" + status + \"t\"](rtrim + \".XMLHT\".memory() + rbuggyQSA);" fullword ascii
    $s6  = "version[preventDefault + \"n\"](innerText.memory(((177, createTextNode, 80) + classNames * 3)), ((unique & 41) - (sortStable + 5" ascii
    $s7  = "version[preventDefault + \"n\"](innerText.memory(((177, createTextNode, 80) + classNames * 3)), ((unique & 41) - (sortStable + 5" ascii
    $s8  = "setter = winnow[abort + \"Objec\" + dataUser](\"WScrip\".memory() + left + \"ell\");" fullword ascii
    $s9  = "innerText = setter[ridentifier + \"andEn\" + classCache + \"nme\".memory() + optSelected + \"rings\"](fnOver + \"%/\") + b + \"u" ascii
    $s10 = "toSelector = \"ilita\", dirruns = \"i\", ridentifier = (function String.prototype.memory() {" fullword ascii
    $s11 = "content = 59;" fullword ascii
    $s12 = "winnow = PI[uniqueID + \"pt\"];" fullword ascii
    $s13 = "funcName = PI[\"WScri\" + msMatchesSelector][\"Creat\".memory() + implementation + \"t\"](sort + \".St\" + guid);" fullword ascii
    $s14 = "version = setter;" fullword ascii
    $s15 = "innerText = setter[ridentifier + \"andEn\" + classCache + \"nme\".memory() + optSelected + \"rings\"](fnOver + \"%/\") + b + \"u" ascii
    $s16 = "eval(unescape(\"%20%20%20%20%20%20%20%20PI%5B%22WScrip%22%20+%20dataUser%5D%5B%22Sle%22%20+%20src%20+%20%22p%22.memory%28%29%5D%" ascii
    $s17 = "argument = 5;" fullword ascii
    $s18 = "wait();" fullword ascii
    $s19 = "function matchedCount() {" fullword ascii
    $s20 = "function when() {" fullword ascii

  condition:
    uint16(0) == 0x6e66 and
    8 of them
}