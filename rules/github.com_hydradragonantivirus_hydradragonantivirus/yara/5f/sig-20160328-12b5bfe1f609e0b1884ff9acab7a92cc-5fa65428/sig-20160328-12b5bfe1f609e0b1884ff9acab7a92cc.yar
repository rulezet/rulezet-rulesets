rule sig_20160328_12b5bfe1f609e0b1884ff9acab7a92cc {
  meta:
    description = "datamaliciousorder - file 20160328_12b5bfe1f609e0b1884ff9acab7a92cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9aa5aadfc5e246c758c10a2c38c9e4fd30fbdabef8260d1a885c7bd2ca97898"

  strings:
    $x1  = "eval(tokens(\"document%20%3D%20%28%22uctor%22%29%3Borig%20%3D%20%28%22s%22%29%2C%20responseHeadersString%20%3D%20%28%22m/2TG%22%" ascii
    $s2  = "for(pipe = (nodeValue | 0); pipe < returnValue[manipulationTarget + \"h\"]; pipe++) {" fullword ascii
    $s3  = "function createTextNode(getWindow, dataShow, processData) {" fullword ascii
    $s4  = "if(currentValue[\"statu\" + orig] == ((Math.pow(315, load) - 98845) - (wrapAll & 253))) {" fullword ascii
    $s5  = "while(currentValue[m + \"yStat\" + properties] != ((1 * load) * (2 + nodeValue))) parts[\"WScrip\" + constructor][\"Slee\" + arg" ascii
    $s6  = "find[\"mo\" + last] = (3 | (isXML - 42));" fullword ascii
    $s7  = "eval(tokens(\"document%20%3D%20%28%22uctor%22%29%3Borig%20%3D%20%28%22s%22%29%2C%20responseHeadersString%20%3D%20%28%22m/2TG%22%" ascii
    $s8  = "(((189 - test) | (36 | apply)));" fullword ascii
    $s9  = "initialInUnit[fnOut + \"ipt\"][marginDiv + \"leep\"](((5253 - a) & (7130 & merge)));" fullword ascii
    $s10 = "find[currentTime + \"File\"](rquery, (load & (57 / matcherFromTokens)));" fullword ascii
    $s11 = "find[\"ty\" + argument + \"e\"] = ((hash * 1) & (hash & 1));" fullword ascii
    $s12 = "mappedTypes(tokens(\"find%20%3D%20initialInUnit%5Bextend%20+%20%22pt%22%5D%5Bindirect%20+%20%22teO%22%20+%20insertAfter%5D%28%22" ascii
    $s13 = "find[\"op\" + properties + \"n\"]();" fullword ascii
    $s14 = "find[clearInterval + \"ite\"](currentValue[ontype + \"seBo\" + rbracket]);" fullword ascii
    $s15 = "bySet[defaultPrevented + \"u\" + hide](rquery);" fullword ascii
    $s16 = "parts[\"WScrip\" + constructor][\"Sleep\"](((global / 12), (progressContexts + 182), (wrapAll & 179), (timer | 4736)));" fullword ascii
    $s17 = "while(currentValue[m + \"yStat\" + properties] != ((1 * load) * (2 + nodeValue))) parts[\"WScrip\" + constructor][\"Slee\" + arg" ascii
    $s18 = "function tokens(parentWindow) {" fullword ascii
    $s19 = "triggerHandler(merge, fnOut, max, fixHook, run);" fullword ascii
    $s20 = "mappedTypes(tokens(\"find%20%3D%20initialInUnit%5Bextend%20+%20%22pt%22%5D%5Bindirect%20+%20%22teO%22%20+%20insertAfter%5D%28%22" ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}