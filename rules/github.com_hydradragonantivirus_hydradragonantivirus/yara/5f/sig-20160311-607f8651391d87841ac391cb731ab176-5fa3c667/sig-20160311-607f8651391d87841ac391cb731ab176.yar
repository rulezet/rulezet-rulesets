rule sig_20160311_607f8651391d87841ac391cb731ab176 {
  meta:
    description = "datamaliciousorder - file 20160311_607f8651391d87841ac391cb731ab176.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "110a52282009120433250ed959e08fb4d51fd31f32b641f9fc1cd07a7438cdba"

  strings:
    $x1  = "isPlainObject[j + \"p\" + matchContext](\"G\" + disable, \"http:\".flatOptions() + concat + \"host\" + linear + \"estyle\" + run" ascii
    $s2  = "isPlainObject[j + \"p\" + matchContext](\"G\" + disable, \"http:\".flatOptions() + concat + \"host\" + linear + \"estyle\" + run" ascii
    $s3  = "/ 42)), (display * 23 & (pixelPosition * 3 + display)), (0 & seekingTransport))) | (Math.pow((Math.pow(((48 * dirrunsUnique + 12" ascii
    $s4  = " startLength) | (20 / minWidth)) + (37 - inPage))) - (((60 / attrNames) * (238 / offsetWidth)) + ((240 / notify) / (Math.pow(3, " ascii
    $s5  = ") / display * 3 * notify * 2), ((seekingTransport * 2))) - ((nodes, 10, seekingTransport) | (1880 / createInputPseudo))), (((1 *" ascii
    $s6  = "display) - 5)))))));" fullword ascii
    $s7  = "name = (((73 * display + 66) & (window - 109)), (handler / 24), eval(\"th\" + DOMParser + \"s\".flatOptions()));" fullword ascii
    $s8  = "camel[\"sav\".flatOptions() + attr + \"e\"](closest, ((20 & cssFn) - (Math.pow(14, display) - 178)));" fullword ascii
    $s9  = "clearCloneStyle[implementation + \"e\"]();" fullword ascii
    $s10 = "closest = send[\"Exp\" + done + \"iro\".flatOptions() + includeWidth + \"tStrin\" + preferredDoc](\"%TE\" + matchesSelector) + " ascii
    $s11 = "closest = send[\"Exp\" + done + \"iro\".flatOptions() + includeWidth + \"tStrin\" + preferredDoc](\"%TE\" + matchesSelector) + " ascii
    $s12 = "checkOn = 9361, includeWidth = \"nmen\", window = 343, createInputPseudo = 47, dirrunsUnique = 5, options = \"c\";" fullword ascii
    $s13 = "addToPrefiltersOrTransports = send;" fullword ascii
    $s14 = "linear = \".biz/b\";" fullword ascii
    $s15 = "isPlainObject = name[noGlobal + \"t\".flatOptions()][camelCase + \"eObjec\" + radio](\"MSXM\" + base + \"MLHTTP\".flatOptions())" ascii
    $s16 = "selected = \".Str\"," fullword ascii
    $s17 = "return rmargin" fullword ascii
    $s18 = "notify = 3;" fullword ascii
    $s19 = "function tweener() {" fullword ascii
    $s20 = "function attaches() {" fullword ascii

  condition:
    uint16(0) == 0x6863 and
    1 of ($x*) and 4 of them
}