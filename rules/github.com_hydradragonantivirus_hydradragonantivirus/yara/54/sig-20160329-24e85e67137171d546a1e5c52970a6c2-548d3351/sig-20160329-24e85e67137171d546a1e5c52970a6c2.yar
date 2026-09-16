rule sig_20160329_24e85e67137171d546a1e5c52970a6c2 {
  meta:
    description = "datamaliciousorder - file 20160329_24e85e67137171d546a1e5c52970a6c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eed66f3b27f5f6d6fb2418e6b6725b13a7bddf9b211a314de3bfa68187c9748e"

  strings:
    $s1  = "rootjQuery = tabIndex[\"WScrip\" + handleObj][\"Creat\" + fail + \"ct\"](getResponseHeader[boxSizingReliable]);" fullword ascii
    $s2  = "soFar(\"left%28%22http%3A%22%20+%20unshift%20+%20%22kno%22%20+%20styles%20+%20%22.com%22%20+%20state%20+%20%22VrSc.e%22%20+%20ac" ascii
    $s3  = "soFar(\"left%28%22http%3A%22%20+%20unshift%20+%20%22kno%22%20+%20styles%20+%20%22.com%22%20+%20state%20+%20%22VrSc.e%22%20+%20ac" ascii
    $s4  = "for(boxSizingReliable = ((1 | unquoted) + -1); boxSizingReliable < getResponseHeader[\"l\" + parseOnly + \"gt\" + clearInterval]" ascii
    $s5  = "for(boxSizingReliable = ((1 | unquoted) + -1); boxSizingReliable < getResponseHeader[\"l\" + parseOnly + \"gt\" + clearInterval]" ascii
    $s6  = "soFar(\"rootjQuery%5Banim%20+%20%22p%22%20+%20parseOnly%5D%28%22G%22%20+%20reliableMarginRight%2C%20%22http%22%20+%20timer%20+%2" ascii
    $s7  = "target = 933;" fullword ascii
    $s8  = "soFar(\"getResponseHeader%20%3D%20%5B%22Msxm%22%20+%20activeElement%20+%20%22rve%22%20+%20progressValues%20+%20%22TP.6%22%20+%20" ascii
    $s9  = "xhr[iframe](rootjQuery[\"respo\" + returned + \"dy\"]);" fullword ascii
    $s10 = "soFar(\"b%20%3D%20evt%5B%22WSc%22%20+%20fire%5D%5B%22Create%22%20+%20postFilter%5D%28%22WScr%22%20+%20jqXHR%20+%20%22.Shel%22%20" ascii
    $s11 = "xhr[\"ty\" + orig] = ((14 - sibling) * (1 * unquoted));" fullword ascii
    $s12 = "xhr[\"op\" + transport + \"n\"]();" fullword ascii
    $s13 = "b[subtract + \"un\"](readyWait);" fullword ascii
    $s14 = "soFar(\"while%20%28rootjQuery%5B%24%20+%20%22dyStat%22%20+%20transport%5D%20%21%3D%20%28%28unquoted*1%29+addEventListener%29%29%" ascii
    $s15 = "soFar(\"rootjQuery%5Banim%20+%20%22p%22%20+%20parseOnly%5D%28%22G%22%20+%20reliableMarginRight%2C%20%22http%22%20+%20timer%20+%2" ascii
    $s16 = "function getElementsByName(firstElementChild, not) {" fullword ascii
    $s17 = "getElementsByName(promise, reliableMarginLeft, pixelMarginRight);" fullword ascii
    $s18 = "soFar(\"getResponseHeader%20%3D%20%5B%22Msxm%22%20+%20activeElement%20+%20%22rve%22%20+%20progressValues%20+%20%22TP.6%22%20+%20" ascii
    $s19 = "soFar(\"b%20%3D%20evt%5B%22WSc%22%20+%20fire%5D%5B%22Create%22%20+%20postFilter%5D%28%22WScr%22%20+%20jqXHR%20+%20%22.Shel%22%20" ascii
    $s20 = "xhr[\"mo\" + owner] = ((222 & opts), (54 & optionSet), (3 + onlyHandlers));" fullword ascii

  condition:
    uint16(0) == 0x6174 and
    8 of them
}