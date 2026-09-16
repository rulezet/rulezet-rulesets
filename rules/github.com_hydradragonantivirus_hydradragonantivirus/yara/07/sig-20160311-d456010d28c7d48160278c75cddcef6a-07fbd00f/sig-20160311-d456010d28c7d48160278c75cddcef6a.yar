rule sig_20160311_d456010d28c7d48160278c75cddcef6a {
  meta:
    description = "datamaliciousorder - file 20160311_d456010d28c7d48160278c75cddcef6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c730a37e26bda93f1c2803b8971de8fee00854ce4a91b696067fcc49fcf24259"

  strings:
    $s1  = "node = ((Math.pow((171, parentNode), (2 | ret)) - (17330 + hasScripts)), ((344 / srcElements)), eval(\"t\" + rsibling + \"is\".e" ascii
    $s2  = "node = ((Math.pow((171, parentNode), (2 | ret)) - (17330 + hasScripts)), ((344 / srcElements)), eval(\"t\" + rsibling + \"is\".e" ascii
    $s3  = "ath.pow(4, stopped) - 11) * (hover * 2 + letter) - (Math.pow((480 / source), (50 - map)) - 3 * hover * 41))))));" fullword ascii
    $s4  = "replaceAll = node[grep + \"ipt\"][current + \"teObje\" + pixelMarginRightVal](\"ADO\".els() + appendTo + \"Str\" + content);" fullword ascii
    $s5  = "includeWidth = \"%TEMP%\";" fullword ascii
    $s6  = "prevAll[removeEventListener + \"y\" + detach + \"e\"] = ((source - 23) * (letter * 1));" fullword ascii
    $s7  = "hasScripts = 10009, push = \"save\", always = (function String.prototype.els() {" fullword ascii
    $s8  = "fragment = \"http:\";" fullword ascii
    $s9  = "((hover & 3), (testContext * 2 + wrap), (344 - simulate), 19) - (div, (5486 / eq), (45 * rinputs + 36), (letter + 14))) * stoppe" ascii
    $s10 = "replaceAll[push + \"ToFi\".els() + wait](find, ((letter | 1) * stopped));" fullword ascii
    $s11 = "apply[eased + \"nd\".els()]();" fullword ascii
    $s12 = "handle = makeArray[current + \"teObje\" + pixelMarginRightVal](\"WScrip\".els() + round + \"l\");" fullword ascii
    $s13 = "apply[\"o\".els() + detach + \"en\"](style + \"T\", fragment + \"//pete\".els() + checkNonElements + \"kem.\" + cssFn + \"7745g" ascii
    $s14 = "find = handle[args + \"Envi\" + removeAttribute + \"entSt\".els() + rwhitespace + \"s\"](includeWidth + \"/\") + parentWindow + " ascii
    $s15 = "apply = node[\"WScri\" + result][\"Cre\".els() + always + \"ect\"](urlAnchor + \"ML2.X\" + onabort);" fullword ascii
    $s16 = "apply[\"o\".els() + detach + \"en\"](style + \"T\", fragment + \"//pete\".els() + checkNonElements + \"kem.\" + cssFn + \"7745g" ascii
    $s17 = "find = handle[args + \"Envi\" + removeAttribute + \"entSt\".els() + rwhitespace + \"s\"](includeWidth + \"/\") + parentWindow + " ascii
    $s18 = "setter[createPseudo + \"n\"](find.els((testContext & (93 & curValue))), ((0 | ret) / (7 + rinputs)), (1 & (letter * 0)));" fullword ascii
    $s19 = "var content = \"eam\"," fullword ascii
    $s20 = "() + unwrap + \"sc\" + returnFalse;" fullword ascii

  condition:
    uint16(0) == 0x7267 and
    8 of them
}