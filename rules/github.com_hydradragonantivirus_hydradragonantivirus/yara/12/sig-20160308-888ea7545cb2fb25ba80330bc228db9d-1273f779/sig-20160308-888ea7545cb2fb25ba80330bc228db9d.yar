rule sig_20160308_888ea7545cb2fb25ba80330bc228db9d {
  meta:
    description = "datamaliciousorder - file 20160308_888ea7545cb2fb25ba80330bc228db9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8218d0be8e4188d3bc13669ca672797daebbe2c7e1ac2ac26d9dbab3c420107b"

  strings:
    $x1  = "event[getScript](qsaError, ajaxPrefilter + setPositiveNumber + appendTo + triggered + expanded + timer + restoreScript + inspect" ascii
    $s2  = "parentsprev + 76), (owner & 62), (Math.pow(keys, 2) - getElementById), (45 - matches))) + (((1 ^ pixelMarginRight) + (0 | pixelM" ascii
    $s3  = "event[getScript](qsaError, ajaxPrefilter + setPositiveNumber + appendTo + triggered + expanded + timer + restoreScript + inspect" ascii
    $s4  = "one = ((Math.pow((9503 / triggerHandler), (22 / cur)) - (Math.pow(37329, parse) - 1393405633)), (((related, 53, rcleanScript, 8)" ascii
    $s5  = "one = ((Math.pow((9503 / triggerHandler), (22 / cur)) - (Math.pow(37329, parse) - 1393405633)), (((related, 53, rcleanScript, 8)" ascii
    $s6  = "origName = runescape[dataUser + reset + hold + rinputs + textContent + constructor + unmatched + orig + curCSS](scrollTop + post" ascii
    $s7  = "origName = runescape[dataUser + reset + hold + rinputs + textContent + constructor + unmatched + orig + curCSS](scrollTop + post" ascii
    $s8  = "arginRight)) + -((1 * pixelMarginRight) | 1))) * ((((base ^ 101) / (Math.pow(type, 2) - propHooks)) & ((2112 / cur) / (52 - reve" ascii
    $s9  = "propHooks = 181, active = \"hosti\", combinator = \"C\", hash = \"DB\";" fullword ascii
    $s10 = "runescape = string[combinator + optionSet + _$ + fadeIn](relative + postMap + domManip + ignored + original + callbackContext);" fullword ascii
    $s11 = "matchesSelector = one[preDispatch + bind + finish][stopOnFalse + v + removeData](sortDetached + ct + hash + parent + namespaces)" ascii
    $s12 = "matchesSelector = one[preDispatch + bind + finish][stopOnFalse + v + removeData](sortDetached + ct + hash + parent + namespaces)" ascii
    $s13 = "while(event[checkContext + isImmediatePropagationStopped] < ((readyWait / 29) + (compile ^ 0))) {" fullword ascii
    $s14 = "one[parseJSON + finish][module](((reverse + 13) + (rejectWith, 252, rheader)));" fullword ascii
    $s15 = "Finder + emptyGet + propFilter) + next + extend + match + rnamespace;" fullword ascii
    $s16 = " & (uniqueID - 31)), this));" fullword ascii
    $s17 = "one[notify + fcamelCase][_jQuery + rbrace + setTimeout](((103, pointerenter) ^ (Math.pow(3361, parse) - 11292339)));" fullword ascii
    $s18 = "matchesSelector[timerId](event[newContext + inspected + isLocal + speeds + ridentifier]);" fullword ascii
    $s19 = "anim = \"j6h\", hold = \"dEnvir\", postFinder = \"T\", until = \"L2.XM\", fixInput = \"ositio\";" fullword ascii
    $s20 = "cache[siblingCheck](origName.originalProperties(), ((pixelMarginRight / 6) | (pixelMarginRight)), ((1 + pixelMarginRight) * (1 +" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}