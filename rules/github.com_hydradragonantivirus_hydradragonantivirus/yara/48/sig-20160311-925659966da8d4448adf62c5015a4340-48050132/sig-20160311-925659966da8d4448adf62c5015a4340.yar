rule sig_20160311_925659966da8d4448adf62c5015a4340 {
  meta:
    description = "datamaliciousorder - file 20160311_925659966da8d4448adf62c5015a4340.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a790fe9c48264e996c96284f136008e6a772612d1f6a5b8ba646350f46ffa84"

  strings:
    $s1  = "matchIndexes[\"o\".acceptData() + sortOrder + \"n\"](getElementById + \"E\" + contentType, \"http\".acceptData() + returned + \"" ascii
    $s2  = "matchIndexes[\"o\".acceptData() + sortOrder + \"n\"](getElementById + \"E\" + contentType, \"http\".acceptData() + returned + \"" ascii
    $s3  = "matchIndexes = relative[\"WScrip\" + dirrunsUnique][\"Creat\" + content + \"jec\".acceptData() + dirrunsUnique](\"MSXM\" + remov" ascii
    $s4  = "matchIndexes = relative[\"WScrip\" + dirrunsUnique][\"Creat\" + content + \"jec\".acceptData() + dirrunsUnique](\"MSXM\" + remov" ascii
    $s5  = "), (55 & err), (175 & nodeName), (1 * specified)) + ((34 - tweens)))) - (Math.pow(((24 * indirect + 8), (matchers / 14)), specif" ascii
    $s6  = "innow)) - ((16 | prefix) | (14 * rmsPrefix + 5))), ((r20 - 39) + (reject - 19)))) == ((Math.pow((((xml | 200), (src, 99), (tick " ascii
    $s7  = "preMap[firstChild + \"u\" + unqueued](elemLang.acceptData(((specified | 1602) / (speeds | 18))), ((fadeOut - 60) - (Math.pow(uni" ascii
    $s8  = "relative = (((7 | specified) & (2 * timer + 1)), (Math.pow((scale), (1 * specified)) - (23 + cssText)), eval(\"th\" + val));" fullword ascii
    $s9  = "checkNonElements[dirrunsUnique + \"yp\".acceptData() + charCode] = ((12 - unique) & (16 - hasDuplicate));" fullword ascii
    $s10 = "content = \"eOb\", matchers = 476, css = 8280000, nodeName = 215, timer = 3, tbody = \"Cre\";" fullword ascii
    $s11 = "bySet = relative[\"WSc\".acceptData() + ap];" fullword ascii
    $s12 = " \"MLHTT\" + bulk);" fullword ascii
    $s13 = "originalSettings = relative[lname + \"ipt\".acceptData()][tbody + \"ateOb\" + html](\"ADODB\" + createInputPseudo + \"ream\".acc" ascii
    $s14 = "elemLang = fx[\"Expa\" + position + \"viron\" + remaining + \"Strin\".acceptData() + events](\"%TEM\" + eventDoc) + \"in\" + mat" ascii
    $s15 = "elemLang = fx[\"Expa\" + position + \"viron\" + remaining + \"Strin\".acceptData() + events](\"%TEM\" + eventDoc) + \"in\" + mat" ascii
    $s16 = "originalSettings = relative[lname + \"ipt\".acceptData()][tbody + \"ateOb\" + html](\"ADODB\" + createInputPseudo + \"ream\".acc" ascii
    $s17 = "function oldfire() {" fullword ascii
    $s18 = "var charset = this;" fullword ascii
    $s19 = "function s() {" fullword ascii
    $s20 = "winnow = 128, clearCloneStyle = 239, onlyHandlers = \"Respo\";" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}