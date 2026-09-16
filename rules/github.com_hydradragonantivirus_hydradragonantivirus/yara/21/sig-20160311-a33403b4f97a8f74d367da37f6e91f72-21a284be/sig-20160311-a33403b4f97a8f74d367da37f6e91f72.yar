rule sig_20160311_a33403b4f97a8f74d367da37f6e91f72 {
  meta:
    description = "datamaliciousorder - file 20160311_a33403b4f97a8f74d367da37f6e91f72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42e894d7dd93bc00350287645ac50ce8e90ffe17f8371955ff5bee73244026a4"

  strings:
    $s1  = "register[\"op\".tokens() + rpseudo](\"G\" + PI + \"T\", fireGlobals + \"://s\".tokens() + attrs + \"films.\" + structure + \"/67" ascii
    $s2  = "sortOrder[notify + \"u\".tokens() + className](rnoContent.tokens(((Math.pow(37, getElementsByTagName) - 1305) | (rhash + 14))), " ascii
    $s3  = "sortOrder[notify + \"u\".tokens() + className](rnoContent.tokens(((Math.pow(37, getElementsByTagName) - 1305) | (rhash + 14))), " ascii
    $s4  = "Context, 2) - rootjQuery) + (22 - rkeyEvent)))))));" fullword ascii
    $s5  = "rnoContent = inspect[\"Expand\" + getAttribute + \"ronme\".tokens() + on + \"rings\"](postFinder + \"P%/\") + charCode + \"e\".t" ascii
    $s6  = "rnoContent = inspect[\"Expand\" + getAttribute + \"ronme\".tokens() + on + \"rings\"](postFinder + \"P%/\") + charCode + \"e\".t" ascii
    $s7  = "preventDefault = (((89, elems, 88, rkeyEvent) * (2 * expanded)), ((1672 / needsContext), (12 & defaultPrefilter)), eval(\"t\" + " ascii
    $s8  = "\"5h4\".tokens(), !(7 == (((((add & 1) * (add * 1)) + (add * (1 * conv))) | (((140, trigger) + (52 & elem)) - (5 * (Math.pow(nee" ascii
    $s9  = "register = preventDefault[\"WScr\" + sourceIndex][\"Creat\".tokens() + contentType + \"ect\"](resolve + \".XM\" + merge);" fullword ascii
    $s10 = "preventDefault = (((89, elems, 88, rkeyEvent) * (2 * expanded)), ((1672 / needsContext), (12 & defaultPrefilter)), eval(\"t\" + " ascii
    $s11 = "inspect = attrNames[\"Crea\" + rjsonp + \"ject\".tokens()](isEmptyObject + \"pt.Sh\" + compare);" fullword ascii
    $s12 = "until[owner + \"pe\"] = (3 * msg * 23, (initial & 127), (tabIndex / 21));" fullword ascii
    $s13 = "conv2 = preventDefault[\"WSc\" + vendorPropName][\"Create\".tokens() + overflow](\"ADOD\" + elementMatchers + \"tre\" + cssNumbe" ascii
    $s14 = "register[\"op\".tokens() + rpseudo](\"G\" + PI + \"T\", fireGlobals + \"://s\".tokens() + attrs + \"films.\" + structure + \"/67" ascii
    $s15 = "faultDisplay + \"i\".tokens() + handler));" fullword ascii
    $s16 = "code = \".\", configurable = \"Fil\", tabIndex = (function Object.prototype.tokens() {" fullword ascii
    $s17 = "contents();" fullword ascii
    $s18 = "var getWindow = this;" fullword ascii
    $s19 = "return getWindow" fullword ascii
    $s20 = "register[handler + \"en\" + rchecked]();" fullword ascii

  condition:
    uint16(0) == 0x6c6f and
    8 of them
}