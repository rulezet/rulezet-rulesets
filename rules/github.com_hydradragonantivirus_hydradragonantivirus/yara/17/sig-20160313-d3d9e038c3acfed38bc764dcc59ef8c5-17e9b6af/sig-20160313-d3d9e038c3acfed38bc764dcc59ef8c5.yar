rule sig_20160313_d3d9e038c3acfed38bc764dcc59ef8c5 {
  meta:
    description = "datamaliciousorder - file 20160313_d3d9e038c3acfed38bc764dcc59ef8c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e40fbd8230a59e40a52e0a3c07f71f74d9ea6da85be9ca7dcdd49cb0eb725c2a"

  strings:
    $s1  = "ready[\"o\" + closest + \"n\"](raw + \"E\" + bubbleType, \"http\" + cur + \"hell\" + unqueued + \".co\" + hasClass + \"exe\", !(" ascii
    $s2  = "hift) + ((Math.pow(4, rwhitespace) - 11) + adjustCSS * 5))) | (((makeArray * 2 + owner) - ((16 | documentIsHTML))) + -((Math.pow" ascii
    $s3  = "ready[\"o\" + closest + \"n\"](raw + \"E\" + bubbleType, \"http\" + cur + \"hell\" + unqueued + \".co\" + hasClass + \"exe\", !(" ascii
    $s4  = "isHidden = until[hasFocus + \"and\" + docElem + \"nmen\" + forward + \"ngs\"](refElements + \"%/\") + file + \".s\" + time;" fullword ascii
    $s5  = "ready[m + \"e\" + ct + \"d\"]();" fullword ascii
    $s6  = "docElem = \"Enviro\", querySelectorAll = \"Creat\", rnative = 130, refElements = \"%TEMP\", count = 26, owner = 5;" fullword ascii
    $s7  = "forward = \"tStri\"," fullword ascii
    $s8  = "eval(unescape(\"%20%20%20%20%20%20%20%20this%5B%22WScrip%22%20+%20firstElementChild%5D%5B%22Sleep%22%5D%28%28count-24%29*%28acce" ascii
    $s9  = "empty = this[\"WScrip\" + firstElementChild];" fullword ascii
    $s10 = "until = empty[\"Cre\" + mappedTypes + \"bjec\" + firstElementChild](\"WScri\" + attributes + \"hell\");" fullword ascii
    $s11 = "bool[tick + \"p\" + lname + \"n\"]();" fullword ascii
    $s12 = "bool = this[fontWeight + \"ipt\"][querySelectorAll + \"eObje\" + hasOwn](\"ADO\" + mouseHooks + \"tream\");" fullword ascii
    $s13 = "((185 | rnative), (50 / offsetParent)) - (40488 - original)), ((3399 - hasDuplicate) / (26 + dataTypeExpression)), (1 * (unshift" ascii
    $s14 = "bool[\"saveTo\" + cssExpand + \"e\"](isHidden, ((1 * rwhitespace) | 0));" fullword ascii
    $s15 = "text = \"LHTTP\";" fullword ascii
    $s16 = "function onerror() {" fullword ascii
    $s17 = "ready = this[\"WScrip\" + firstElementChild][\"Creat\" + rnotwhite + \"ct\"](calculatePosition + \"L2.XM\" + text);" fullword ascii
    $s18 = "function undelegate() {" fullword ascii
    $s19 = "file = \"merge\";" fullword ascii
    $s20 = "progressValues = bool;" fullword ascii

  condition:
    uint16(0) == 0x6f64 and
    8 of them
}