rule sig_20160328_dde981b70ea627c4c742fc85a6b1fe22 {
  meta:
    description = "datamaliciousorder - file 20160328_dde981b70ea627c4c742fc85a6b1fe22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eac2a463806346072558a6285b096f2430a77f653532250fe342c3a58d8255a9"

  strings:
    $x1  = "eval(parse(\"startLength%20%3D%20%28%22oty%22%29%3B%20unmatched%20%3D%20%28%22ateOb%22%29%3B%20matchers%20%3D%20%28%22Sav%22%29%" ascii
    $s2  = "tmp[getAll](value[\"respo\" + targets + \"ody\"]);" fullword ascii
    $s3  = "event[parentOffset + \"n\"](processData);" fullword ascii
    $s4  = "while(value[\"readyS\" + getAttribute] != ((onlyHandlers / 39) / (camel + 25))) colgroup[\"WScr\" + key][\"Sleep\"](((groups - 4" ascii
    $s5  = "while(value[\"readyS\" + getAttribute] != ((onlyHandlers / 39) / (camel + 25))) colgroup[\"WScr\" + key][\"Sleep\"](((groups - 4" ascii
    $s6  = "opt[\"WScr\" + key][\"Sleep\"](((tr, 235, rclickable, 347) + (Math.pow(position, 2) - innerText)));" fullword ascii
    $s7  = "curElem(jsonProp, dirruns, targets, submit);" fullword ascii
    $s8  = "remove(parse(\"processData%20%3D%20event%5BfireGlobals%20+%20%22dEn%22%20+%20always%20+%20%22onm%22%20+%20opener%20+%20%22tri%22" ascii
    $s9  = "remove(parse(\"conditionFn%20%3D%20%5B%22Msxm%22%20+%20postMap%20+%20%22erve%22%20+%20parentsUntil%20+%20%22TP.6%22%20+%20origin" ascii
    $s10 = "for(rtrim = ((0 / hasContent) | (0 | opts)); rtrim < conditionFn[\"l\" + count + \"h\"]; rtrim++) {" fullword ascii
    $s11 = "colgroup = opt = textContent = border = matchContext.support();" fullword ascii
    $s12 = "tmp[\"mo\" + expanded] = 3;" fullword ascii
    $s13 = "tmp[\"t\" + setMatched + \"p\" + defaultPrefilter] = structure;" fullword ascii
    $s14 = "remove(parse(\"processData%20%3D%20event%5BfireGlobals%20+%20%22dEn%22%20+%20always%20+%20%22onm%22%20+%20opener%20+%20%22tri%22" ascii
    $s15 = "remove(parse(\"tmp%20%3D%20opt%5B%22WScri%22%20+%20handleObj%5D%5B%22Creat%22%20+%20rbuggyQSA%20+%20%22ct%22%5D%28xhrSuccessStat" ascii
    $s16 = "remove(parse(\"value%5B%22o%22%20+%20sortDetached%20+%20%22e%22%20+%20fragment%5D%28%22G%22%20+%20matcherOut%2C%20%22http%3A/%22" ascii
    $s17 = "Content%20%3D%20%2817%29%3BdefineProperty%20%3D%20%28%22ructor%22%29%2C%20elems%20%3D%20%28%22.s%22%29%2C%20sortDetached%20%3D%2" ascii
    $s18 = "remove(parse(\"conditionFn%20%3D%20%5B%22Msxm%22%20+%20postMap%20+%20%22erve%22%20+%20parentsUntil%20+%20%22TP.6%22%20+%20origin" ascii
    $s19 = "opt[jsonProp + \"ipt\"][setMatcher + \"ep\"](((20081 & second) / (84, which)));" fullword ascii
    $s20 = "if(value[td + \"u\" + realStringObj] == ((styles), (2064 / find), (200 | overflowY))) {" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}