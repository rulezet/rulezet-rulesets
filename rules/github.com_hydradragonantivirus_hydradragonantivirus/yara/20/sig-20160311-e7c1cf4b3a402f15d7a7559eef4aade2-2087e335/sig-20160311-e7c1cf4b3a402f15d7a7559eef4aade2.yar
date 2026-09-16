rule sig_20160311_e7c1cf4b3a402f15d7a7559eef4aade2 {
  meta:
    description = "datamaliciousorder - file 20160311_e7c1cf4b3a402f15d7a7559eef4aade2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12f95c4df3d372be7e0d6580cf396176e9188c6ef6abf95c3b882bfed356236e"

  strings:
    $s1  = "preDispatch[step + \"p\".setGlobalEval() + compiled + \"n\"](isSuccess + \"E\" + expanded, \"http:\".setGlobalEval() + time + \"" ascii
    $s2  = "preDispatch[step + \"p\".setGlobalEval() + compiled + \"n\"](isSuccess + \"E\" + expanded, \"http:\".setGlobalEval() + time + \"" ascii
    $s3  = " letterSpacing + \"r35y44\" + computeStyleTests, !(((((1 * file) * (1 + clearCloneStyle)) & (1 * (scriptCharset - 8))) + ((((cor" ascii
    $s4  = "sort = statusCode[\"Expand\" + parentOffset + \"ronm\" + radioValue + \"Str\".setGlobalEval() + find](\"%TEM\" + elemdisplay) + " ascii
    $s5  = "then = (((12 - round) * (6 & rscriptType)), ((5 + escapedWhitespace) + (30 / round)), eval(\"th\" + easing));" fullword ascii
    $s6  = "handler[\"ty\" + setMatchers + \"e\".setGlobalEval()] = ((15 - originAnchor) / (516 / rsingleTag));" fullword ascii
    $s7  = "fcamelCase[returnValue + \"oFi\" + param](sort, ((Math.pow(150, escapedWhitespace) - 22323), (outermost, 92, multipleContexts, 1" ascii
    $s8  = "fcamelCase[returnValue + \"oFi\" + param](sort, ((Math.pow(150, escapedWhitespace) - 22323), (outermost, 92, multipleContexts, 1" ascii
    $s9  = "temp = \"eObj\";" fullword ascii
    $s10 = "fcamelCase = then[global + \"rip\" + ap][\"Creat\".setGlobalEval() + temp + \"ect\"](evt + \".Strea\" + hasData);" fullword ascii
    $s11 = "sort = statusCode[\"Expand\" + parentOffset + \"ronm\" + radioValue + \"Str\".setGlobalEval() + find](\"%TEM\" + elemdisplay) + " ascii
    $s12 = "attachEvent = then[\"WScr\".setGlobalEval() + adjustCSS];" fullword ascii
    $s13 = "rejectWith[\"R\" + rCRLF](sort.setGlobalEval((unit | 73)), clearCloneStyle, (1 * (children - 12)));" fullword ascii
    $s14 = "preDispatch[\"se\".setGlobalEval() + checkNonElements + \"d\"]();" fullword ascii
    $s15 = "), (file * 2)));" fullword ascii
    $s16 = "statusCode = attachEvent[\"Create\" + subtract + \"ct\"](clientY + \"pt.S\".setGlobalEval() + rmultiDash);" fullword ascii
    $s17 = "clearCloneStyle = 0, computeStyleTests = \"y5\", outermost = 241, nodes = 138;" fullword ascii
    $s18 = "easing = \"is\";" fullword ascii
    $s19 = "global = \"WSc\";" fullword ascii
    $s20 = "function eventPath() {" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    8 of them
}