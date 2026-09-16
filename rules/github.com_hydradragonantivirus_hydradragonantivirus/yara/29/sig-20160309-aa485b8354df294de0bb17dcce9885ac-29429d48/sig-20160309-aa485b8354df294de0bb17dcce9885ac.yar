rule sig_20160309_aa485b8354df294de0bb17dcce9885ac {
  meta:
    description = "datamaliciousorder - file 20160309_aa485b8354df294de0bb17dcce9885ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23e108e58ecf69e40a9ca20ac6c5e9eeba37e645c03b85c29b2069eec44c6780"

  strings:
    $s1  = "doneName[tfoot](param.input(), (0 | (preexisting * 0)), ((body - 43) + -(method, 197, processData, 1)));" fullword ascii
    $s2  = "delegateTarget = wrapMap[parsed + documentElement + start][selectors + focus + selectedIndex + compare](curPosition + beforeunlo" ascii
    $s3  = "delegateTarget[fixInput](string + hasDuplicate, rtrim + support + udataOld + statusText + to + animation + unquoted + propFix + " ascii
    $s4  = "delegateTarget = wrapMap[parsed + documentElement + start][selectors + focus + selectedIndex + compare](curPosition + beforeunlo" ascii
    $s5  = "set = wrapMap[close + configurable + contextBackup][selectors + focus + getElementsByClassName + hidden + onerror + opt](setOffs" ascii
    $s6  = "set = wrapMap[close + configurable + contextBackup][selectors + focus + getElementsByClassName + hidden + onerror + opt](setOffs" ascii
    $s7  = "conv = delegateTarget[defer + letterSpacing + pnum];" fullword ascii
    $s8  = "resolveValues = dirruns[needsContext + xhrFields + pop + hidden + compare](destElements + start + fire + mappedTypes + mappedTyp" ascii
    $s9  = "resolveValues = dirruns[needsContext + xhrFields + pop + hidden + compare](destElements + start + fire + mappedTypes + mappedTyp" ascii
    $s10 = "delegateTarget[fixInput](string + hasDuplicate, rtrim + support + udataOld + statusText + to + animation + unquoted + propFix + " ascii
    $s11 = "wrapMap = (((Math.pow(57, matchContext) - 3183) | (Math.pow(originalEvent, 2) - rneedsContext)), (((1 | wrapInner) * (75 - prefe" ascii
    $s12 = "focus = \"at\", processData = 71, removeChild = \"nv\", defer = \"Respon\";" fullword ascii
    $s13 = "origName[forward + find + noGlobal] = (0 & preexisting);" fullword ascii
    $s14 = "wrap = \"%TEMP\";" fullword ascii
    $s15 = "toSelector = 26, support = \"p:/\", matchContext = 2, compare = \"ject\";" fullword ascii
    $s16 = "forward = \"po\"," fullword ascii
    $s17 = "host[fromCharCode]();" fullword ascii
    $s18 = "host = set;" fullword ascii
    $s19 = "param = resolveValues[th + raw + removeChild + last + ownerDocument + msg + memory + timers + expando + letterSpacing](wrap + se" ascii
    $s20 = "tMatcher) + height + offsetWidth + checked + matchers + random;" fullword ascii

  condition:
    uint16(0) == 0x6966 and
    8 of them
}