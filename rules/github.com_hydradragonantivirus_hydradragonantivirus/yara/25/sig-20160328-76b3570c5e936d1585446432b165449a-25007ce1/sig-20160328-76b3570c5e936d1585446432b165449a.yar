rule sig_20160328_76b3570c5e936d1585446432b165449a {
  meta:
    description = "datamaliciousorder - file 20160328_76b3570c5e936d1585446432b165449a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d389f04f2a28a738241ba2401f677b81afa00a167a6bbea4ffc1182c5791468"

  strings:
    $s1  = "eval(bind(\"matchContext%20%3D%20%2874952%29%2C%20cleanData%20%3D%20%281%29%2C%20subtract%20%3D%20%28%22ject%22%29%2C%20doScroll" ascii
    $s2  = " createCache(bind(\"s%5B%22o%22%20+%20adown%20+%20%22en%22%5D%28camel%20+%20%22T%22%2C%20unwrap%20+%20%22p%3A/%22%20+%20hasFocus" ascii
    $s3  = "push[send + \"od\" + onlyHandlers] = ((41 - compile));" fullword ascii
    $s4  = "function bind(getWindow) {" fullword ascii
    $s5  = "  finalValue[\"WSc\" + innerHTML][\"Sl\" + activeElement](((memory - 1621) | (close & 5032)));" fullword ascii
    $s6  = "prevUntil = finalValue = detach = rneedsContext = Sizzle.completeDeferred();" fullword ascii
    $s7  = " while(s[\"read\" + off + \"e\"] != (1 + (emptyStyle))) finalValue[top + \"pt\"][removeProp + \"eep\"](((102 & reject) | (1 * cu" ascii
    $s8  = " while(s[\"read\" + off + \"e\"] != (1 + (emptyStyle))) finalValue[top + \"pt\"][removeProp + \"eep\"](((102 & reject) | (1 * cu" ascii
    $s9  = "function fired(outermostContext, attaches, overrideMimeType) {" fullword ascii
    $s10 = "  push[doScroll + \"te\"](s[hide + \"nseBod\" + rsibling]);" fullword ascii
    $s11 = " if(s[focusin + \"tat\" + charCode] == ((7378 / next) & (30 * unshift + 28))) {" fullword ascii
    $s12 = "  prevUntil[\"WScr\" + pdataOld][\"Sleep\"](((matchContext | 8240) / (tween | 1)));" fullword ascii
    $s13 = "push[\"ty\" + adown + \"e\"] = ((1 | cleanData) & (1 * cleanData));" fullword ascii
    $s14 = "  push[param + \"ToF\" + curCSS](addBack, ((doneName & 3) | (grep, 13, rbrace, 0)));" fullword ascii
    $s15 = "eval(bind(\"matchContext%20%3D%20%2874952%29%2C%20cleanData%20%3D%20%281%29%2C%20subtract%20%3D%20%28%22ject%22%29%2C%20doScroll" ascii
    $s16 = "hell%22%29%3B%20activeElement%20%3D%20%28%22eep%22%29%3B%20defaultExtra%20%3D%20%28%22sjo.ex%22%29%3B%20XMLHttpRequest%20%3D%20%" ascii
    $s17 = "function handleObj(ridentifier) {" fullword ascii
    $s18 = "function transport(href) {" fullword ascii
    $s19 = " createCache(bind(\"domManip%20%3D%20%5BclearInterval%20+%20%222.Serv%22%20+%20jsonp%20+%20%22LHTT%22%20+%20newSelector%20+%20%2" ascii
    $s20 = " createCache(bind(\"addBack%20%3D%20prepend%5B%22Expan%22%20+%20adjustCSS%20+%20%22onmen%22%20+%20after%20+%20%22ngs%22%5D%28sel" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}