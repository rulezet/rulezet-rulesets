rule sig_20160328_f8a91efbc19b07a27532ddfba839b966 {
  meta:
    description = "datamaliciousorder - file 20160328_f8a91efbc19b07a27532ddfba839b966.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdbb3e7219b6e83b37f46aa425811911885f65734208c824e5cb1d846ae1b472"

  strings:
    $s1  = "pend + \"leep\"](((resolveContexts - 23) + (getBoundingClientRect / 25)));" fullword ascii
    $s2  = "while(callbackInverse[\"rea\" + callbackExpect + \"ate\"] != ((hasCompare * 4) | (postFilter * 2))) clearTimeout[rmargin + \"ipt" ascii
    $s3  = "triggerHandler[getElementsByName + \"eTo\" + off](props, ((68 / tick) & (1 * postFilter)));" fullword ascii
    $s4  = "while(callbackInverse[\"rea\" + callbackExpect + \"ate\"] != ((hasCompare * 4) | (postFilter * 2))) clearTimeout[rmargin + \"ipt" ascii
    $s5  = "callbackInverse = clearTimeout[\"WSc\" + suffix][\"Crea\" + rkeyEvent + \"ject\"](disconnectedMatch[colgroup]);" fullword ascii
    $s6  = "function returnTrue(pipe) {" fullword ascii
    $s7  = "when(ifModified, postFilter, value, styles);" fullword ascii
    $s8  = "fired(tweeners, pageY, newUnmatched, getElementsByName, noGlobal);" fullword ascii
    $s9  = "buildFragment[overflow + \"un\"](props);" fullword ascii
    $s10 = "triggerHandler[delegate + \"e\" + slideUp]();" fullword ascii
    $s11 = "triggerHandler[\"mo\" + value] = ((3 | newUnmatched));" fullword ascii
    $s12 = "triggerHandler[\"ty\" + nodeNameSelector] = ((37 / truncate) + (0 | newUnmatched));" fullword ascii
    $s13 = "return unescape(pipe);" fullword ascii
    $s14 = "checkClone(off, delegate, classes, matcherFromTokens, hasCompare);" fullword ascii
    $s15 = "} catch(getPropertyValue) {}" fullword ascii
    $s16 = "function divStyle() {" fullword ascii
    $s17 = "function fired() {" fullword ascii
    $s18 = "function attr() {" fullword ascii
    $s19 = "if(callbackInverse[testContext + \"atus\"] == ((tuples | 128) | (until, 136))) {" fullword ascii
    $s20 = "callbackInverse[\"s\" + apply + \"n\" + specialEasing]();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}