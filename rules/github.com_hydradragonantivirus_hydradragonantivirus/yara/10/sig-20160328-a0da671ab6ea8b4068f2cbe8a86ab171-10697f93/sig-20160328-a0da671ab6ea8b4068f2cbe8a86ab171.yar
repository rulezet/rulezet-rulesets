rule sig_20160328_a0da671ab6ea8b4068f2cbe8a86ab171 {
  meta:
    description = "datamaliciousorder - file 20160328_a0da671ab6ea8b4068f2cbe8a86ab171.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cbaec95893045142f7b1f3715ea9bef7cf88efe249b88481b376a8b8d209e55"

  strings:
    $s1  = "while (defer[\"read\" + high + \"ate\"] != ((4 | src) | (Math.pow(3, globalEval) - 5))) propFix[preventDefault + \"ipt\"][size](" ascii
    $s2  = "while (defer[\"read\" + high + \"ate\"] != ((4 | src) | (Math.pow(3, globalEval) - 5))) propFix[preventDefault + \"ipt\"][size](" ascii
    $s3  = "add(ajaxTransport(\"defer%5BstartLength%20+%20%22e%22%20+%20restoreScript%5D%28%22G%22%20+%20slideDown%20+%20%22T%22%2C%20boxSiz" ascii
    $s4  = "if (defer[\"stat\" + contextBackup] == ((190 / isXML) * (2 * globalEval + 1) + (rkeyEvent & 11))) {" fullword ascii
    $s5  = "propFix = select = scrollTop = relatedTarget = tick.getResponseHeader();" fullword ascii
    $s6  = "split[getAllResponseHeaders + \"pe\"] = (1 * guaranteedUnique);" fullword ascii
    $s7  = "add(ajaxTransport(\"defer%5BstartLength%20+%20%22e%22%20+%20restoreScript%5D%28%22G%22%20+%20slideDown%20+%20%22T%22%2C%20boxSiz" ascii
    $s8  = "function nodeType(setRequestHeader) {" fullword ascii
    $s9  = "defer[\"s\" + marginDiv + \"n\" + rfocusable]();" fullword ascii
    $s10 = "split[\"m\" + parsed + \"de\"] = ((3 | guaranteedUnique) & (1 * charset));" fullword ascii
    $s11 = "split[\"op\" + marginDiv + \"n\"]();" fullword ascii
    $s12 = "add(ajaxTransport(\"split%20%3D%20propFix%5B%22WScri%22%20+%20selected%5D%5B%22Creat%22%20+%20fxNow%20+%20%22ct%22%5D%28input%20" ascii
    $s13 = "add(ajaxTransport(\"split%5Bnid%20+%20%22i%22%20+%20delegateType%5D%28defer%5B%22res%22%20+%20stored%20+%20%22eBody%22%5D%29%3B" ascii
    $s14 = "add(ajaxTransport(\"select%5BpreventDefault%20+%20%22ipt%22%5D%5BflatOptions%20+%20%22p%22%5D%28%28%28siblingCheck-759%29*%28glo" ascii
    $s15 = "add(ajaxTransport(\"select%5B%22WScri%22%20+%20selected%5D%5B%22S%22%20+%20nonce%20+%20%22eep%22%5D%28%28%282*globalEval*577*glo" ascii
    $s16 = "function ajaxTransport(resolveValues) {" fullword ascii
    $s17 = "split[parseOnly + \"eToF\" + prefilterOrFactory](tokenCache, (guaranteedUnique * (2 & globalEval)));" fullword ascii
    $s18 = "add(ajaxTransport(\"select%5BpreventDefault%20+%20%22ipt%22%5D%5BflatOptions%20+%20%22p%22%5D%28%28%28siblingCheck-759%29*%28glo" ascii
    $s19 = "add(ajaxTransport(\"split%5Bnid%20+%20%22i%22%20+%20delegateType%5D%28defer%5B%22res%22%20+%20stored%20+%20%22eBody%22%5D%29%3B" ascii
    $s20 = "display[removeChild + \"n\"](tokenCache);" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}