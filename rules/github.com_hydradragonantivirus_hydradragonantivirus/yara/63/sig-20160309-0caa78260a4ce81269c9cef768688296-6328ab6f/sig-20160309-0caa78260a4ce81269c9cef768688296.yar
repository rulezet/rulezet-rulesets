rule sig_20160309_0caa78260a4ce81269c9cef768688296 {
  meta:
    description = "datamaliciousorder - file 20160309_0caa78260a4ce81269c9cef768688296.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "402370950a2ada40d9bd82f06863d93e9437a83b8bb0f873e718c601e032c2b2"

  strings:
    $s1  = "fadeOut[success + p](pnum, finish + duplicates + attributes + guid + keepScripts + readyWait + dest + actualDisplay + node + pre" ascii
    $s2  = "configurable = createButtonPseudo[contents + mouseleave + random][camelKey + keepScripts + indirect + dataUser](rchecked + doAni" ascii
    $s3  = "configurable = createButtonPseudo[contents + mouseleave + random][camelKey + keepScripts + indirect + dataUser](rchecked + doAni" ascii
    $s4  = "(12 & contentDocument))) & (Math.pow(((1 | host) ^ (1 + -replaceAll)), ((18 | newUnmatched) / 3 * doScroll)) - ((43 & createTwee" ascii
    $s5  = "createButtonPseudo = (((48 | hide) + (Math.pow(14, delegateType) - 176)), (((height - 218) / (Symbol - 29)), this));" fullword ascii
    $s6  = "pend + func + unquoted, !(replaceAll < (((((8 - isEmptyObject) * (3 & delegateType) + (1 * replaceAll)) ^ ((1 ^ delegateType) ^ " ascii
    $s7  = "getJSON = fadeOut[curPosition + thead + tween + prefilterOrFactory];" fullword ascii
    $s8  = "selector = createButtonPseudo[contents + mouseleave + random];" fullword ascii
    $s9  = "resolve = reject[ridentifier + grep + handle + lname + fast + href + window](tweens + swap + rmultiDash) + num + uid + keepData " ascii
    $s10 = "configurable[children + clearTimeout + s](resolve, ((2 + replaceAll) & 2));" fullword ascii
    $s11 = "transports[high + fns] = (0 ^ replaceAll);" fullword ascii
    $s12 = "fadeOut[success + p](pnum, finish + duplicates + attributes + guid + keepScripts + readyWait + dest + actualDisplay + node + pre" ascii
    $s13 = "contents = \"WS\"," fullword ascii
    $s14 = "}, 3), host = 9, keepData = \"rt\";" fullword ascii
    $s15 = "event = \".Shell\"," fullword ascii
    $s16 = "reject = selector[token + lastChild + elemData + scale + sortDetached](winnow + attr + toggleClass + event);" fullword ascii
    $s17 = "resolve = reject[ridentifier + grep + handle + lname + fast + href + window](tweens + swap + rmultiDash) + num + uid + keepData " ascii
    $s18 = "swap = \"EMP\", rescape = \"WSc\", camelKey = \"Cre\", token = \"Create\";" fullword ascii
    $s19 = "when = \"i\";" fullword ascii
    $s20 = "handle = \"ndEnv\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}