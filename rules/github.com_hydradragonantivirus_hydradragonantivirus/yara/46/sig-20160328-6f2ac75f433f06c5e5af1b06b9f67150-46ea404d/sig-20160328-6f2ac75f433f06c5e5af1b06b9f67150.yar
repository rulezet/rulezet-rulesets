rule sig_20160328_6f2ac75f433f06c5e5af1b06b9f67150 {
  meta:
    description = "datamaliciousorder - file 20160328_6f2ac75f433f06c5e5af1b06b9f67150.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd571c6928d042a6c3fc489697bff6bccfe690a01df32e18b4ad8e50389012d5"

  strings:
    $x1  = "eval(input(\"ready%20%3D%20%28%22t%22%29%2C%20checkContext%20%3D%20%28%22i%22%29%2C%20leadingRelative%20%3D%20%28%22le%22%29%2C%" ascii
    $s2  = "setPositiveNumber[linear + \"eToFi\" + leadingRelative](currentTarget, ((originalEvent - 60) / (select, 5)));" fullword ascii
    $s3  = "defaultPrefilter(input(\"currentTarget%20%3D%20fireGlobals%5Brelative%20+%20%22andEn%22%20+%20css%20+%20%22mentSt%22%20+%20getEl" ascii
    $s4  = "rparentsprev[\"WSc\" + animation + \"t\"][needsContext + \"ep\"](((Math.pow(48177, ct) - 2320963329) / (condense | 12)));" fullword ascii
    $s5  = "defaultPrefilter(input(\"currentTarget%20%3D%20fireGlobals%5Brelative%20+%20%22andEn%22%20+%20css%20+%20%22mentSt%22%20+%20getEl" ascii
    $s6  = "defaultPrefilter(input(\"fireGlobals%20%3D%20value%5B%22WScri%22%20+%20newContext%5D%5B%22Creat%22%20+%20overrideMimeType%20+%20" ascii
    $s7  = "defaultPrefilter(input(\"stateString%5BajaxHandleResponses%20+%20%22en%22%5D%28defineProperty%20+%20%22T%22%2C%20configurable%20" ascii
    $s8  = "defaultPrefilter(input(\"createTextNode%28letterSpacing%20+%20%22p%3A/%22%20+%20onreadystatechange%20+%20%22gionto%22%20+%20pdat" ascii
    $s9  = "for (mozMatchesSelector = ((0 & removeEvent) / (1 * transports)); mozMatchesSelector < undelegate[related + \"th\"]; mozMatchesS" ascii
    $s10 = "for (mozMatchesSelector = ((0 & removeEvent) / (1 * transports)); mozMatchesSelector < undelegate[related + \"th\"]; mozMatchesS" ascii
    $s11 = "defaultPrefilter(input(\"stateString%20%3D%20rparentsprev%5BrealStringObj%20+%20%22rip%22%20+%20ready%5D%5B%22Creat%22%20+%20ver" ascii
    $s12 = "function addClass(contentType, eventDoc, addGetHookIf) {" fullword ascii
    $s13 = "function content() {" fullword ascii
    $s14 = "cssProps(forward, select);" fullword ascii
    $s15 = "content(setMatchers);" fullword ascii
    $s16 = "defaultPrefilter(input(\"fireGlobals%20%3D%20value%5B%22WScri%22%20+%20newContext%5D%5B%22Creat%22%20+%20overrideMimeType%20+%20" ascii
    $s17 = "grep(eq, getClientRects, param);" fullword ascii
    $s18 = "pointerenter = rparentsprev = optDisabled = value = swap.head();" fullword ascii
    $s19 = "setPositiveNumber[_ + \"od\" + rtagName] = ((36 / condense) | (2 & params));" fullword ascii
    $s20 = "stateString[\"se\" + selection]();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}