rule sig_20160311_4bbd7d3f14ebd320de546e7fb4c8a536 {
  meta:
    description = "datamaliciousorder - file 20160311_4bbd7d3f14ebd320de546e7fb4c8a536.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f568002426bac519e57a53d972d40584d8f0a3653e4b79da58c98a3ed5b55317"

  strings:
    $x1  = "rnoInnerhtml[promise + \"en\".tokenCache()](originalEvent + \"E\" + matchAnyContext, \"http:\" + identifier + \"gov.s\".tokenCac" ascii
    $s2  = "Until) & 3 * (cssHooks & 3) * (rscriptType, 219, isPlainObject, 5) * (siblings - 20)) + (Math.pow(((processData / 42) + always)," ascii
    $s3  = "groups[\"R\" + contents + \"n\".tokenCache()](mouseenter.tokenCache((Math.pow(flag, 2) - getBoundingClientRect)), ((1 & always) " ascii
    $s4  = "scrollTop = ((Math.pow(22, on) - 461) * (cssHooks | 3), ((getScript + 2) & returned), eval(\"th\" + dir + \"s\".tokenCache()));" fullword ascii
    $s5  = "groups[\"R\" + contents + \"n\".tokenCache()](mouseenter.tokenCache((Math.pow(flag, 2) - getBoundingClientRect)), ((1 & always) " ascii
    $s6  = " keepScripts)))), ((((8 + done) | (1 * getScript)) | ((148 - html) + (126, offsetParent))) & ((32 + always) - (234, isPlainObjec" ascii
    $s7  = "removeEventListener = \"%TEMP%\";" fullword ascii
    $s8  = "xpr + \"r35y44\" + condense, !((((((219 & firstElementChild) + (67 | getAll)) / ((66 - firstChild) & (246, fxNow, 14))) - ((Math" ascii
    $s9  = "rnoInnerhtml[promise + \"en\".tokenCache()](originalEvent + \"E\" + matchAnyContext, \"http:\" + identifier + \"gov.s\".tokenCac" ascii
    $s10 = "w((dataUser + 58), on) - (243, fx)), (11 * returned * 5 / (on + 9))))) > always));" fullword ascii
    $s11 = "41, on) - 1631), (status, 2)) - (checkClone / 18)) - (Math.pow((pdataOld / 9), (always + 1)) - (eventHandle - 401))) - ((Math.po" ascii
    $s12 = " (2 * on * 23 / (pixelPosition * 2 + on))) - ((55 * on + 6), returned * 5 * returned, (19 * done + 6), (Math.pow(curCSSTop, 2) -" ascii
    $s13 = "t, 30)) * ((sortOrder + 223), (Math.pow(done, 2) - a)) * ((4 - always)) * ((2 + always) - (1 + stored))), (((Math.pow((Math.pow(" ascii
    $s14 = "ow((computed, 86, trigger), (2 & cssHooks)) - (1430 / onabort)) + ((1 & always) + (1 & always)))), ((((38 + rtagName) * 2 + prev" ascii
    $s15 = "mouseenter = dataTypes[isHidden + \"Enviro\" + charCode + \"trings\".tokenCache()](removeEventListener + \"/\") + token + \"e\" " ascii
    $s16 = "mouseenter = dataTypes[isHidden + \"Enviro\" + charCode + \"trings\".tokenCache()](removeEventListener + \"/\") + token + \"e\" " ascii
    $s17 = "contents = \"u\";" fullword ascii
    $s18 = "lastModified[promise + \"en\"]();" fullword ascii
    $s19 = "token = \"defin\";" fullword ascii
    $s20 = "dataTypes = fireWith[animation + \"Obj\" + hasFocus](\"WScri\".tokenCache() + uid + \"hell\");" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}