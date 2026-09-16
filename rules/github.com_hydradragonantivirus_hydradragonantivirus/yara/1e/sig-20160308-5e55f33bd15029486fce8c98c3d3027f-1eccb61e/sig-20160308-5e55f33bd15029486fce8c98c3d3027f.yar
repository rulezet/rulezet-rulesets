rule sig_20160308_5e55f33bd15029486fce8c98c3d3027f {
  meta:
    description = "datamaliciousorder - file 20160308_5e55f33bd15029486fce8c98c3d3027f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd6ffa80241dead0e852c3a94b6a3049e7d9defdc20d0198eba7b7de03c1a2b0"

  strings:
    $s1  = "content = elementMatchers[fadeToggle + compile][arr + undelegate + map + div1](getScript + props + scale + defaultView + related" ascii
    $s2  = "content = elementMatchers[fadeToggle + compile][arr + undelegate + map + div1](getScript + props + scale + defaultView + related" ascii
    $s3  = "while(content[responses + ct + transports] < (2 * onlyHandlers * 2 - (originalSettings + 3))) {" fullword ascii
    $s4  = "dirruns = checkContext[timeout + hasContent + acceptData](timers + clone + ridentifier + body + undelegate + childNodes);" fullword ascii
    $s5  = "owner[rtrim + ret + postFilter](content[doc + td + pageYOffset + xhr]);" fullword ascii
    $s6  = "content[once + start](fast + show + propHooks, getElementById + clientLeft + soFar + src + responseText + callbackInverse + clas" ascii
    $s7  = "content[once + start](fast + show + propHooks, getElementById + clientLeft + soFar + src + responseText + callbackInverse + clas" ascii
    $s8  = "compilerCache = dirruns[cors + dataTypeOrTransport + responseFields + reliableMarginLeft + handlers + trim + rcomma + querySelec" ascii
    $s9  = "compilerCache = dirruns[cors + dataTypeOrTransport + responseFields + reliableMarginLeft + handlers + trim + rcomma + querySelec" ascii
    $s10 = "owner = elementMatchers[fadeToggle + compile][arr + slideToggle + acceptData](open + pageYOffset + err + progressValues);" fullword ascii
    $s11 = "elementMatchers[attrs + cssText + compile][checked + prev](((addCombinator ^ 104), (promise ^ 170), (fire & 51), (onlyHandlers *" ascii
    $s12 = "elementMatchers[attrs + cssText + compile][checked + prev](((addCombinator ^ 104), (promise ^ 170), (fire & 51), (onlyHandlers *" ascii
    $s13 = "implicitRelative = 25, amd = \"gb4\", closest = \"ope\", pixelPositionVal = \"%TEMP\", fire = 63;" fullword ascii
    $s14 = "elementMatchers = (((30 ^ inspectPrefiltersOrTransports) ^ (263 | preMap)), (((5 / originalProperties) * (1 & resolveContexts))," ascii
    $s15 = "content[startTime]();" fullword ascii
    $s16 = "sNames + teardown + rsibling + hide + amd, !((((75 / implicitRelative) * 2 / ((e * 2))) * ((resolveContexts & 1))) == resolveCon" ascii
    $s17 = "torAll](pixelPositionVal + box) + defaultPrefilter + remaining + uniqueSort + parseHTML + hold + reliableMarginLeft;" fullword ascii
    $s18 = "checkContext = elementMatchers[attrs + doAnimation + filter];" fullword ascii
    $s19 = "fireGlobals = base + resolve;" fullword ascii
    $s20 = "owner[closest + curPosition]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}