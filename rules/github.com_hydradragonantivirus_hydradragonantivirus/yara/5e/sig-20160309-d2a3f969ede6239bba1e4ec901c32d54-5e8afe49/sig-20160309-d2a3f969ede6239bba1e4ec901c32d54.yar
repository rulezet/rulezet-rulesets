rule sig_20160309_d2a3f969ede6239bba1e4ec901c32d54 {
  meta:
    description = "datamaliciousorder - file 20160309_d2a3f969ede6239bba1e4ec901c32d54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f55ff94d28123eea2783e0f59754d73222caa83e577e7513dd724d95131abbd"

  strings:
    $s1  = "createPseudo[keyCode](lname, createPositionalPseudo + lock + opener + risSimple + contextBackup + responseText + crossDomain + _" ascii
    $s2  = "view = bindType[isSuccess + get + parsed + converters + close + uniqueSort](Data + prototype) + source + show + onreadystatechan" ascii
    $s3  = "view = bindType[isSuccess + get + parsed + converters + close + uniqueSort](Data + prototype) + source + show + onreadystatechan" ascii
    $s4  = "queueHooks + pixelMarginRightVal + root + matchContext + initialInUnit, !((((((2838 / undelegate), (112 - checked), (0 / bind)) " ascii
    $s5  = "host[tmp + define + filter + statusText + eventDoc] = ((1 + detach) * (0 / cssHooks));" fullword ascii
    $s6  = " conv, 226, selection) * (Math.pow(4, selection) - 11) * (pageX * 5));" fullword ascii
    $s7  = "bindType = pop[expand + pseudos + boolHook](globalEventContext + defaultValue + key + pseudo);" fullword ascii
    $s8  = "tokenCache = (((35, diff), (Math.pow(48, selection) - 2246), (tweener * 2 + pageX)), ((2 + detach), this));" fullword ascii
    $s9  = "tokenCache[margin + isPlainObject][slideToggle]((53 - curElem) * (5 & fns) * (2 ^ detach) * (2 + detach) * (65, iNoClone) * (66," ascii
    $s10 = "| ((1 * pageX) * (72, safeActiveElement, 115, detach))) ^ (((0 ^ detach) ^ (5 - fns)) ^ (0 ^ pageX))) + (((21, overflow, 1) & (o" ascii
    $s11 = "perator - 33)) | ((pageX ^ (0 | contains)) - ((45 + url) - 2 * selection * 2)))) == selection));" fullword ascii
    $s12 = "JSON = \"seBod\", binary = \"R\", resolve = \"Respo\", handler = \"eO\", lname = \"GET\", isArray = \"MSXML2\";" fullword ascii
    $s13 = "tokenCache[margin + isPlainObject][slideToggle]((53 - curElem) * (5 & fns) * (2 ^ detach) * (2 + detach) * (65, iNoClone) * (66," ascii
    $s14 = "createInputPseudo = binary + hasOwn + eventDoc;" fullword ascii
    $s15 = "scrollTo[username + matcher] = ((1 & pageX) | (1 * detach));" fullword ascii
    $s16 = "createPseudo[keyCode](lname, createPositionalPseudo + lock + opener + risSimple + contextBackup + responseText + crossDomain + _" ascii
    $s17 = "onreadystatechange = \"cr\", detach = 0, isPlainObject = \"Script\";" fullword ascii
    $s18 = "host = scrollTo;" fullword ascii
    $s19 = "operator = 34;" fullword ascii
    $s20 = "get = \"and\", uniqueSort = \"trings\", lock = \"tp:/\";" fullword ascii

  condition:
    uint16(0) == 0x6361 and
    8 of them
}