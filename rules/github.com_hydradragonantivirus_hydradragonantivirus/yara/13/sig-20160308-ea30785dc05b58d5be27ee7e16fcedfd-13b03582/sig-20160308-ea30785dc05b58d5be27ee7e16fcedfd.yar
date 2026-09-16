rule sig_20160308_ea30785dc05b58d5be27ee7e16fcedfd {
  meta:
    description = "datamaliciousorder - file 20160308_ea30785dc05b58d5be27ee7e16fcedfd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ec13fdc194b756d8db2a92d5953190fab3fcc3e0fef06d6a6bc316d56d9d164"

  strings:
    $s1  = "buildFragment[genFx](isTrigger, modified + noConflict + th + offsetHeight + forward + detectDuplicates + delegateType + matcherO" ascii
    $s2  = "tokenCache[domManip](top.addEventListener(), (setFilters + -1), ((m | 104), (content * 2 + id), (234, second, 12), (propFilter /" ascii
    $s3  = "tokenCache[domManip](top.addEventListener(), (setFilters + -1), ((m | 104), (content * 2 + id), (234, second, 12), (propFilter /" ascii
    $s4  = "keyCode = tokenize[parse + preFilters + options + cache](restoreScript + removeClass + margin + chainable + off);" fullword ascii
    $s5  = "while (buildFragment[charset + eased] < ((2 ^ requestHeadersNames) ^ 0)) {" fullword ascii
    $s6  = "attr[outermostContext + tr][node + defaultExtra + hasOwn](((rtypenamespace, 32, hooks, 178) - (open / 6)));" fullword ascii
    $s7  = "allTypes[detectDuplicates + keepScripts + ct + firstDataType](top, (2 | (self, 10, pageX, 0)));" fullword ascii
    $s8  = "updateFunc = \"ment\", m = 136, keepScripts = \"ave\", lock = \"Res\";" fullword ascii
    $s9  = "buildFragment[genFx](isTrigger, modified + noConflict + th + offsetHeight + forward + detectDuplicates + delegateType + matcherO" ascii
    $s10 = "var content = 95," fullword ascii
    $s11 = "forward = \"a\";" fullword ascii
    $s12 = "allTypes[reset + abort](buildFragment[lock + document + converters + isArray]);" fullword ascii
    $s13 = "ut + name + optall + val, !((((((1 * time) & (2 | id)) ^ ((0 & setFilters) & (0 ^ setFilters))) * (((0 / option) | (78 / minWidt" ascii
    $s14 = "attr = ((1 * time) * (5 & animated) * (1 * time) * 3, (setFilters, this));" fullword ascii
    $s15 = "lastChild)) + ((2 & time) ^ 1)))) > remove));" fullword ascii
    $s16 = "buildFragment[state + xml]();" fullword ascii
    $s17 = "firing[wait + parsed + start] = ((ajaxSetup, 58, propFilter) / (28 | fireGlobals));" fullword ascii
    $s18 = "off = \"ll\", wait = \"pos\", keyHooks = \"E\", preFilters = \"eateOb\";" fullword ascii
    $s19 = "buildFragment = attr[_jQuery + setOffset + tr][t + resolveValues + nType + fromCharCode](readyState + webkitMatchesSelector + sp" ascii
    $s20 = "top = keyCode[tbody + namespace + camel + updateFunc + success + cacheURL](clearCloneStyle + ct + keyHooks + crossDomain) + qsa " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}