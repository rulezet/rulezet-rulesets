rule sig_20160311_9e9018f233298cd88295252e1078b6a0 {
  meta:
    description = "datamaliciousorder - file 20160311_9e9018f233298cd88295252e1078b6a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e689625a19dd75f3522fa071af851d535807fbe4e31f15eaeca930580400b70b"

  strings:
    $s1  = "098) - (active + 26)) + ((done / 45) + (Math.pow(requestHeaders, 2) - visible))))));" fullword ascii
    $s2  = ", (15 - matchAnyContext), (2 * contextBackup * 3 * requestHeaders * 2, (Math.pow(open, 2) - wait), 0));" fullword ascii
    $s3  = "url[isPlainObject + \"en\"](firingIndex + \"T\", sortOrder + \"//tha\".fragment() + uid + \".biz\" + copy + \"letha\" + risSimpl" ascii
    $s4  = "Data) - 10907) - (cssText / 28)) + ((Math.pow(tweens, 2) - proxy) / (360 / dataAttr))) - (Math.pow(2 * (contextBackup + 0) * (is" ascii
    $s5  = "getAttribute[wrapInner + \"un\".fragment()](createElement.fragment(((6 * requestHeaders + 5) + (Math.pow(showHide, 2) - classes)" ascii
    $s6  = "createElement = removeEvent[unbind + \"Env\" + content + \"entStr\".fragment() + submit](\"%TEMP\" + camelCase) + \"par\" + sele" ascii
    $s7  = "getAttribute[wrapInner + \"un\".fragment()](createElement.fragment(((6 * requestHeaders + 5) + (Math.pow(showHide, 2) - classes)" ascii
    $s8  = "createElement = removeEvent[unbind + \"Env\" + content + \"entStr\".fragment() + submit](\"%TEMP\" + camelCase) + \"par\" + sele" ascii
    $s9  = "Function & 5), (cssPrefixes * (82 / left))) - ((186, unique, 1469) - (preexisting, 49, mozMatchesSelector)))) * (((Math.pow((5 *" ascii
    $s10 = "getScript = \"Res\", trigger = \"Str\", wait = 21718;" fullword ascii
    $s11 = "preMap = \"saveTo\", sortOrder = \"http:\", done = 990, leadingRelative = 4;" fullword ascii
    $s12 = "\".fragment() + view, !((((((msFullscreenElement / 21) - (uniqueSort * 2 + cssPrefixes)) + -((31 & prop) - (63 - left))) | (((1 " ascii
    $s13 = "set = ((Math.pow((23 + calculatePosition), (100 / margin)) - (11041 | after)), ((129, startLength), (6 + button), (221 & curPosi" ascii
    $s14 = " register) & 1) + (cssPrefixes + -1))) + (Math.pow((((matchIndexes, 14, calculatePosition) / (44 - register)) * (3 | _removeData" ascii
    $s15 = "set = ((Math.pow((23 + calculatePosition), (100 / margin)) - (11041 | after)), ((129, startLength), (6 + button), (221 & curPosi" ascii
    $s16 = "writable[\"ty\" + createComment + \"e\".fragment()] = (1 + register);" fullword ascii
    $s17 = "url[isPlainObject + \"en\"](firingIndex + \"T\", sortOrder + \"//tha\".fragment() + uid + \".biz\" + copy + \"letha\" + risSimpl" ascii
    $s18 = "addGetHookIf = 17, clone = \"MSX\", special = \"ct\", button = 62, requestHeaders = 5, mapped = \"teOb\";" fullword ascii
    $s19 = "content = \"ironm\";" fullword ascii
    $s20 = "after = 11664, uid = \"ihost\", round = \"clo\", tweens = 181;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}