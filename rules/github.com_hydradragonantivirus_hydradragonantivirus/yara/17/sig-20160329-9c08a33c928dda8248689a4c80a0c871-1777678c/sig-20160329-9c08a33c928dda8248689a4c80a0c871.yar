rule sig_20160329_9c08a33c928dda8248689a4c80a0c871 {
  meta:
    description = "datamaliciousorder - file 20160329_9c08a33c928dda8248689a4c80a0c871.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9367e434ffc715589c3bec7ea0be70e6913f54b0f354cf3ee9a2511d2e7cbefc"

  strings:
    $s1  = "sibling(\"radio%20%3D%20preexisting%5B%22WScri%22%20+%20setMatched%5D%5B%22Create%22%20+%20keepScripts%20+%20%22t%22%5D%28relate" ascii
    $s2  = "Target%20+%20%22DB.Str%22%20+%20newContext%29%3B\");" fullword ascii
    $s3  = "if (hooks[getClass + \"tus\"] == ((Math.pow(getResponseHeader, 2) - createInputPseudo) & (52, getElementsByTagName, 85, parse)))" ascii
    $s4  = "function ajaxTransport(getComputedStyle) {" fullword ascii
    $s5  = "sibling(\"pushStack%5B%22WScr%22%20+%20bind%5D%5B%22Sl%22%20+%20disableScript%5D%28%28%28activeElement%29*%285%7Cstring%29*%282%" ascii
    $s6  = "sibling(\"pushStack%5B%22WScr%22%20+%20bind%5D%5B%22Sl%22%20+%20disableScript%5D%28%28%28activeElement%29*%285%7Cstring%29*%282%" ascii
    $s7  = "radio[\"ty\" + jsonp] = ((suffix - 10) / (wrapInner | 28));" fullword ascii
    $s8  = "sibling(\"radio%20%3D%20preexisting%5B%22WScri%22%20+%20setMatched%5D%5B%22Create%22%20+%20keepScripts%20+%20%22t%22%5D%28relate" ascii
    $s9  = "content();" fullword ascii
    $s10 = "function content() {" fullword ascii
    $s11 = "sibling(\"fail%20%3D%20pushStack%5B%22WScri%22%20+%20setMatched%5D%5B%22Cre%22%20+%20escapedWhitespace%20+%20%22bject%22%5D%28cu" ascii
    $s12 = "sibling(\"hooks%5B%22op%22%20+%20show%20+%20%22n%22%5D%28detectDuplicates%20+%20%22ET%22%2C%20fadeOut%20+%20%22p%3A//zl%22%20+%2" ascii
    $s13 = "radio[\"mo\" + not] = ((29 + check) / 29);" fullword ascii
    $s14 = "hooks[\"s\" + show + \"nd\"]();" fullword ascii
    $s15 = "sibling(\"settings%20%3D%20%5BhookFn%20+%20%22l2.S%22%20+%20stored%20+%20%22erXML%22%20+%20rnative%20+%20%226.0%22%2C%20a%20+%20" ascii
    $s16 = "radio[\"SaveTo\" + toArray](safeActiveElement, (scrollLeft * 2));" fullword ascii
    $s17 = "radio[\"Wr\" + boxSizingReliable](hooks[\"resp\" + num + \"dy\"]);" fullword ascii
    $s18 = "sibling(\"preexisting%5Btokens%20+%20%22t%22%5D%5BsetMatcher%20+%20%22e%22%20+%20dataType%5D%28%28%287006%26setMatchers%29-%2825" ascii
    $s19 = "fail[\"Ru\" + duplicates](safeActiveElement);" fullword ascii
    $s20 = "sibling(\"preexisting%5Btokens%20+%20%22t%22%5D%5BsetMatcher%20+%20%22e%22%20+%20dataType%5D%28%28%287006%26setMatchers%29-%2825" ascii

  condition:
    uint16(0) == 0x6874 and
    8 of them
}