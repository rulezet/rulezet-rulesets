rule sig_20160311_31964fb05482b835b40d5958089b4e81 {
  meta:
    description = "datamaliciousorder - file 20160311_31964fb05482b835b40d5958089b4e81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f057bca2f5612542aecdaa354a550ff471e6bc89c532eed96c39980e6e419f8"

  strings:
    $s1  = "rclass[\"o\".optSelected() + complete + \"n\"](parseJSON + \"E\" + completed, \"http\".optSelected() + nodes + \"erdick\" + sele" ascii
    $s2  = "& (Math.pow((4 | split), (44 / push_native)) - (180 / support)))) | ((((585 / qualifier) & (169 - hash)) & ((Math.pow(96, groups" ascii
    $s3  = "oldfire[\"sav\" + bubbleType + \"ile\"](postMap, ((504 / support) - (16 | byElement)));" fullword ascii
    $s4  = ") - 9118) | (Math.pow(markFunction, 2) - context))), ((2552 / username), (1 + checkDisplay)), (((118 - innerHTML) - (47 - byElem" ascii
    $s5  = "optgroup[fcamelCase + \"n\".optSelected()](postMap.optSelected(((write - 123) & (Math.pow(fns, 2) - focus))), (0 | (valueIsBorde" ascii
    $s6  = "optgroup[fcamelCase + \"n\".optSelected()](postMap.optSelected(((write - 123) & (Math.pow(fns, 2) - focus))), (0 | (valueIsBorde" ascii
    $s7  = "m/8\" + responses + \"5g\".optSelected(), !(((Math.pow(((3 & rsibling) & (3 | valueIsBorderBox)), ((1 * groups) | 2)) - (qualifi" ascii
    $s8  = "checkContext = (((56 & prevAll) + (116 / valueIsBorderBox)), (Math.pow((43, split, 5), (groups | 2)) - (Math.pow(byElement, 2) -" ascii
    $s9  = "checkContext = (((56 & prevAll) + (116 / valueIsBorderBox)), (Math.pow((43, split, 5), (groups | 2)) - (Math.pow(byElement, 2) -" ascii
    $s10 = "postMap = originalProperties[always + \"ndEnv\" + teardown + \"nmentS\".optSelected() + self + \"s\"](timerId + \"MP%/\") + stat" ascii
    $s11 = "postMap = originalProperties[always + \"ndEnv\" + teardown + \"nmentS\".optSelected() + self + \"s\"](timerId + \"MP%/\") + stat" ascii
    $s12 = "oldfire = checkContext[\"WScr\" + access][\"Creat\".optSelected() + unbind + \"ject\"](onabort + \".St\" + fragment + \"m\".optS" ascii
    $s13 = "oldfire = checkContext[\"WScr\" + access][\"Creat\".optSelected() + unbind + \"ject\"](onabort + \".St\" + fragment + \"m\".optS" ascii
    $s14 = "rclass[\"o\".optSelected() + complete + \"n\"](parseJSON + \"E\" + completed, \"http\".optSelected() + nodes + \"erdick\" + sele" ascii
    $s15 = "dir = \"h\", setRequestHeader = (function String.prototype.optSelected() {" fullword ascii
    $s16 = "function addGetHookIf() {" fullword ascii
    $s17 = "position[rcssNum + \"ose\".optSelected()]();" fullword ascii
    $s18 = "unbind = \"eOb\";" fullword ascii
    $s19 = "swing = \"on\", hash = 51, newSelector = 28, eased = 656, teardown = \"iro\";" fullword ascii
    $s20 = "rsibling = 3, support = 18;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}