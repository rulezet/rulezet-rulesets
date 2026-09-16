rule sig_20160328_bf224a9363ad3850201823cd5bd2116f {
  meta:
    description = "datamaliciousorder - file 20160328_bf224a9363ad3850201823cd5bd2116f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b915d486f7292ea4e16d37e86b3319d89930eaf2f49671ccf5700f4626db8cd"

  strings:
    $x1  = "eval(width(\"postDispatch%20%3D%20%28%22Msxml2%22%29%2C%20parseXML%20%3D%20%28%22op%22%29%3Btweener%20%3D%20%28%22t%22%29%2C%20f" ascii
    $s2  = "while(rcleanScript[xhrSupported + \"tat\" + notifyWith] != ((2 | originalOptions) * 2)) completeDeferred[\"WSc\" + responseHeade" ascii
    $s3  = "while(rcleanScript[xhrSupported + \"tat\" + notifyWith] != ((2 | originalOptions) * 2)) completeDeferred[\"WSc\" + responseHeade" ascii
    $s4  = "node[documentIsHTML + \"te\"](rcleanScript[requestHeadersNames + \"onseB\" + raw]);" fullword ascii
    $s5  = "\"Sl\" + prevObject](((structure) & (244 - requestHeaders)));" fullword ascii
    $s6  = "rcleanScript = completeDeferred[\"WScrip\" + tweener][\"Cre\" + rprotocol + \"bject\"](pointerenter[context]);" fullword ascii
    $s7  = "rcleanScript[\"s\" + speed + \"d\"]();" fullword ascii
    $s8  = "node[code + \"pe\"] = (divStyle, 81, rheaders, 1);" fullword ascii
    $s9  = "matcherFromGroupMatchers(width(\"pointerenter%20%3D%20%5Bhandlers%20+%20%222.Serv%22%20+%20apply%20+%20%22HTTP.6%22%20+%20nodeVa" ascii
    $s10 = "matcherFromGroupMatchers(width(\"node%20%3D%20hooks%5Btoken%20+%20%22t%22%5D%5Brquery%20+%20%22Object%22%5D%28getJSON%20+%20%22B" ascii
    $s11 = "matcherFromGroupMatchers(width(\"node%20%3D%20hooks%5Btoken%20+%20%22t%22%5D%5Brquery%20+%20%22Object%22%5D%28getJSON%20+%20%22B" ascii
    $s12 = "pdataOld[\"R\" + rcombinators + \"n\"](margin);" fullword ascii
    $s13 = "matcherFromGroupMatchers(width(\"completeDeferred%5Bnamespace%20+%20%22ript%22%5D%5Btokenize%20+%20%22e%22%20+%20multipleContext" ascii
    $s14 = "matcherFromGroupMatchers(width(\"rcleanScript%5BparseXML%20+%20%22en%22%5D%28fontWeight%20+%20%22ET%22%2C%20preMap%20+%20%22p%3A" ascii
    $s15 = "matcherFromGroupMatchers(width(\"completeDeferred%5Bnamespace%20+%20%22ript%22%5D%5Btokenize%20+%20%22e%22%20+%20multipleContext" ascii
    $s16 = "function computed(pop, isReady, _removeData) {" fullword ascii
    $s17 = "matcherFromGroupMatchers(width(\"rcleanScript%5BparseXML%20+%20%22en%22%5D%28fontWeight%20+%20%22ET%22%2C%20preMap%20+%20%22p%3A" ascii
    $s18 = "eval(width(\"postDispatch%20%3D%20%28%22Msxml2%22%29%2C%20parseXML%20%3D%20%28%22op%22%29%3Btweener%20%3D%20%28%22t%22%29%2C%20f" ascii
    $s19 = "function width(headers) {" fullword ascii
    $s20 = "animate(requestHeaders, guid);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}