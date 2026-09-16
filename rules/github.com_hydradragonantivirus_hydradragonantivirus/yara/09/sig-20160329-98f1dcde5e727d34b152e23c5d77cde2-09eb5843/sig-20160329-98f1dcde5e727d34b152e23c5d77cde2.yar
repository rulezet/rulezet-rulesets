rule sig_20160329_98f1dcde5e727d34b152e23c5d77cde2 {
  meta:
    description = "datamaliciousorder - file 20160329_98f1dcde5e727d34b152e23c5d77cde2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfab6ce726964295487de86806b9580fa8ccf1dd0e25838a55dbc03c57222e0b"

  strings:
    $s1  = "innerText(\"while%20%28responses%5B%22rea%22%20+%20cos%20+%20%22ate%22%5D%20%21%3D%20%28%282*rkeyEvent%29%26%2815%2Cnext%2C4%29%" ascii
    $s2  = "innerText(\"traditional%20%3D%20%5Boverflow%20+%20%222.Serv%22%20+%20beforeunload%20+%20%22MLHTTP%22%20+%20restoreScript%2C%20%2" ascii
    $s3  = "if (responses[visible + \"us\"] == ((rkeyEvent | 0) * (Math.pow(addHandle, 2) - sortDetached) * 2 * (rkeyEvent) * (5 & callbackN" ascii
    $s4  = "if (responses[visible + \"us\"] == ((rkeyEvent | 0) * (Math.pow(addHandle, 2) - sortDetached) * 2 * (rkeyEvent) * (5 & callbackN" ascii
    $s5  = "replaceAll(unbind, getPropertyValue, outermostContext, restoreScript, check);" fullword ascii
    $s6  = "responses = seekingTransport[\"WScrip\" + rheader][\"Crea\" + rnamespace + \"ect\"](traditional[defer]);" fullword ascii
    $s7  = "innerText(\"traditional%20%3D%20%5Boverflow%20+%20%222.Serv%22%20+%20beforeunload%20+%20%22MLHTTP%22%20+%20restoreScript%2C%20%2" ascii
    $s8  = "innerText(\"while%20%28responses%5B%22rea%22%20+%20cos%20+%20%22ate%22%5D%20%21%3D%20%28%282*rkeyEvent%29%26%2815%2Cnext%2C4%29%" ascii
    $s9  = "for (defer = ((testContext / 7) | (check - 42)); defer < traditional[\"len\" + setOffset]; defer++) {" fullword ascii
    $s10 = "delay(rkeyEvent, iterator);" fullword ascii
    $s11 = "innerText(\"animated%20%3D%20matchers%5BboxSizingReliableVal%20+%20%22dEnvir%22%20+%20siblings%20+%20%22Strin%22%20+%20find%5D%2" ascii
    $s12 = "innerText(\"writable%20%3D%20parsed%5B%22WSc%22%20+%20style%5D%5B%22Crea%22%20+%20easing%20+%20%22bje%22%20+%20getClientRects%5D" ascii
    $s13 = "function delay(getAttribute, overflowX) {" fullword ascii
    $s14 = "innerText(\"writable%20%3D%20parsed%5B%22WSc%22%20+%20style%5D%5B%22Crea%22%20+%20easing%20+%20%22bje%22%20+%20getClientRects%5D" ascii
    $s15 = "writable[acceptData + \"o\" + self] = ((2 + position) & (3 | addHandle));" fullword ascii
    $s16 = "writable[nidselect + \"p\" + hasData + \"n\"]();" fullword ascii
    $s17 = "responses[rchecked + \"en\" + type]();" fullword ascii
    $s18 = "matchers[\"Ru\" + eased](animated);" fullword ascii
    $s19 = "animate(insertAfter, unbind, argument);" fullword ascii
    $s20 = "innerText(\"writable%5B%22t%22%20+%20createPositionalPseudo%20+%20%22e%22%5D%20%3D%20%28%283*callbackName+2%29/%28getPropertyVal" ascii

  condition:
    uint16(0) == 0x6d69 and
    8 of them
}