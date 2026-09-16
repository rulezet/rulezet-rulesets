rule sig_20160328_3eef8bdcd1666f5ff2c893884cb05319 {
  meta:
    description = "datamaliciousorder - file 20160328_3eef8bdcd1666f5ff2c893884cb05319.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58237da31f2a7c224e174384eb9e177ec1a0b9f24e31414c4a7431ab288b9c0d"

  strings:
    $s1  = "eval(flag(\"opener%20%3D%20%2839%29%2C%20aup%20%3D%20%28%22de%22%29%2C%20readyList%20%3D%20%28%22.3.0%22%29%2C%20nextUntil%20%3D" ascii
    $s2  = "compareDocumentPosition(flag(\"getter%28%22htt%22%20+%20delegateCount%20+%20%22/th%22%20+%20iNoClone%20+%20%22ark%22%20+%20token" ascii
    $s3  = "compareDocumentPosition(flag(\"queue%20%3D%20defaultDisplay%5BerrorCallback%20+%20%22ndEn%22%20+%20seekingTransport%20+%20%22onm" ascii
    $s4  = "jsonpCallback[\"WSc\" + step + \"t\"][setRequestHeader + \"ep\"]((Math.pow((Math.pow(resolveWith, 2) - slideDown), 2) - (Math.po" ascii
    $s5  = "second[\"mo\" + aup] = ((180 / requestHeaders) / (18 - disconnectedMatch));" fullword ascii
    $s6  = "compareDocumentPosition(flag(\"rmultiDash%20%3D%20%5B%22Msx%22%20+%20dir%20+%20%22rverXM%22%20+%20abort%20+%20%22.6.0%22%2C%20pa" ascii
    $s7  = "jsonpCallback[\"WSc\" + step + \"t\"][setRequestHeader + \"ep\"]((Math.pow((Math.pow(resolveWith, 2) - slideDown), 2) - (Math.po" ascii
    $s8  = "rnoContent(fireGlobals, restoreScript, abort, contains, _jQuery);" fullword ascii
    $s9  = "compareDocumentPosition(flag(\"getter%28%22htt%22%20+%20delegateCount%20+%20%22/th%22%20+%20iNoClone%20+%20%22ark%22%20+%20token" ascii
    $s10 = " + curCSSTop][\"Slee\" + opacity]((Math.pow((194 - firstElementChild), (14 - dataTypeExpression)) - (Math.pow(5009, opt) - 25084" ascii
    $s11 = "function rnoContent(lastChild, script, shift) {" fullword ascii
    $s12 = "chEvent, 2) - fail)));" fullword ascii
    $s13 = "for(node = ((rclickable & 0) / (rheaders + 1)); node < rmultiDash[\"len\" + rjsonp + \"th\"]; node++) {" fullword ascii
    $s14 = "compareDocumentPosition(flag(\"defaultDisplay%20%3D%20nidselect%5B%22WSc%22%20+%20curCSSTop%5D%5B%22Creat%22%20+%20nextUntil%20+" ascii
    $s15 = "while(eventDoc[_evalUrl + \"ySta\" + prevUntil] != (Math.pow((opener / 13), (opt | 2)) - (opt * 2 + closest))) jsonpCallback[\"W" ascii
    $s16 = "while(eventDoc[_evalUrl + \"ySta\" + prevUntil] != (Math.pow((opener / 13), (opt | 2)) - (opt * 2 + closest))) jsonpCallback[\"W" ascii
    $s17 = "function ajaxTransport(implicitRelative, hash, hidden) {" fullword ascii
    $s18 = "function getter() {" fullword ascii
    $s19 = "Creat%22%29%3B%20requestHeaders%20%3D%20%2830%29%3Bvar%20fireGlobals%20%3D%20%28%22/%22%29%2C%20stateString%20%3D%20%28%22/Sq7%2" ascii
    $s20 = "compareDocumentPosition(flag(\"queue%20%3D%20defaultDisplay%5BerrorCallback%20+%20%22ndEn%22%20+%20seekingTransport%20+%20%22onm" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}