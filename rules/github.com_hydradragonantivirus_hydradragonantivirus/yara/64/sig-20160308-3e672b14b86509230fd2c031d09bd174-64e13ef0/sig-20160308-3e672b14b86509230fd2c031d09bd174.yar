rule sig_20160308_3e672b14b86509230fd2c031d09bd174 {
  meta:
    description = "datamaliciousorder - file 20160308_3e672b14b86509230fd2c031d09bd174.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d2c59156178675df87ec98fabd10440d7f33036932555b058d70d756e484352"

  strings:
    $s1  = "msMatchesSelector[visibility + emptyGet](s[readyState + host + checkContext]);" fullword ascii
    $s2  = "tick[_data + qsa][compile + rhash](((Math.pow(54, prevAll) - 2852) ^ win * 3 * prevAll * 2));" fullword ascii
    $s3  = "AnyContext | 0) + (getBoundingClientRect, 117, matchAnyContext))) - ((1500 / originalOptions)))), (((5 | list) ^ (Math.pow(18, p" ascii
    $s4  = "s[appendTo](closest, setFilters + getElementsByName + last + undelegate + timeStamp + rnamespace + mouseenter + progress + _remo" ascii
    $s5  = "base = \"r\", specified = \"onm\", temp = \"send\", css = 6, getElementsByName = \"ttp\", response = \"Scrip\";" fullword ascii
    $s6  = " | ((6 & css) * (Math.pow(4, prevAll) - 10) + (matcherOut & 5))) ^ (interval * ((5 & clearTimeout) * (3 & prevAll) + (96 / close" ascii
    $s7  = "tick[push + base + addCombinator + deep][parseHTML](((siblings + 5825) - win * 5 * active * 3 * win * 3));" fullword ascii
    $s8  = "veData, !(pdataCur < (Math.pow((((3 | async) & ((8 - async) - (1, string, 5))) + (Math.pow(((list + 3) & (prevAll ^ 8)), ((match" ascii
    $s9  = "s[appendTo](closest, setFilters + getElementsByName + last + undelegate + timeStamp + rnamespace + mouseenter + progress + _remo" ascii
    $s10 = "len[global](_load.progressValues(), (async & 1), ((prevAll ^ 35) - (stateVal - 47)));" fullword ascii
    $s11 = "msMatchesSelector[checkbox + fireWith + event + destElements](_load, ((originalProperties - 41) ^ (originalOptions - 27)));" fullword ascii
    $s12 = "revAll) - 303)), ((responses * 11 + position) / (196 / bySet)), ((2 | prevAll) | 0))) - ((((round & 55) ^ (curOffset * 2 + win))" ascii
    $s13 = "dataTypes[teardown + checkbox + clearQueue] = ((letterSpacing * 2) - (originalProperties & 61));" fullword ascii
    $s14 = "s = tick[_data + qsa][onreadystatechange + filters + rquickExpr](tag + inPage + noConflict + then);" fullword ascii
    $s15 = "s[temp]();" fullword ascii
    $s16 = "var host = \"espons\"," fullword ascii
    $s17 = "hookFn[pushStack + destElements] = (code / 37);" fullword ascii
    $s18 = "tick = (((175 & func) + (21 * prevAll + 14)), (((win & 3) & (prevAll + 0)), this));" fullword ascii
    $s19 = "JSON = tick[_data + qsa];" fullword ascii
    $s20 = "while (s[globalEventContext + results + fxNow] < (1 * prevAll) * (1 + matchAnyContext)) {" fullword ascii

  condition:
    uint16(0) == 0x7866 and
    8 of them
}