rule sig_20160329_8e1cbffe78ee62d124b1dcc30a99460d {
  meta:
    description = "datamaliciousorder - file 20160329_8e1cbffe78ee62d124b1dcc30a99460d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d987011c2213571c7e6aa33ea5b062c620b61b2da054feae1facf7660e62a913"

  strings:
    $s1  = "documentElement[get + \"ript\"][fired](((Math.pow(9967, evt) - 99331089) / (evt | 2)));" fullword ascii
    $s2  = "window(\"isArray%5Bundelegate%20+%20%22p%22%20+%20extra%20+%20%22n%22%5D%28ridentifier%20+%20%22E%22%20+%20timeStamp%2C%20%22htt" ascii
    $s3  = "window(\"reliableMarginLeft%20%3D%20parts%5BresponseText%20+%20%22andE%22%20+%20rheaders%20+%20%22mentS%22%20+%20div1%5D%28%22%2" ascii
    $s4  = "eventDoc[queue + \"o\" + dirruns] = (31 - interval);" fullword ascii
    $s5  = "parts[\"R\" + temp](reliableMarginLeft);" fullword ascii
    $s6  = "function conditionFn(using, targets) {" fullword ascii
    $s7  = "isArray = startTime[\"WScri\" + converters][\"Crea\" + traditional + \"bject\"](sibling[responseHeaders]);" fullword ascii
    $s8  = "for (responseHeaders = (0 / (isHidden * 2 * isHidden * 2)); responseHeaders < sibling[\"l\" + mouseenter]; responseHeaders++) {" fullword ascii
    $s9  = "TEMP%22%20+%20updateFunc%29%20+%20%22boolHo%22%20+%20pixelMarginRight%20+%20%22.s%22%20+%20s%3B\");" fullword ascii
    $s10 = "window(\"while%20%28isArray%5Bsend%20+%20%22tat%22%20+%20extra%5D%20%21%3D%20%28%28getElementsByClassName*2%29*%28getElementsByC" ascii
    $s11 = "function rscriptType(step, i) {" fullword ascii
    $s12 = "window(\"isArray%5Bundelegate%20+%20%22p%22%20+%20extra%20+%20%22n%22%5D%28ridentifier%20+%20%22E%22%20+%20timeStamp%2C%20%22htt" ascii
    $s13 = "function getAttributeNode(newDefer, adjustCSS, prevAll) {" fullword ascii
    $s14 = "window(\"reliableMarginLeft%20%3D%20parts%5BresponseText%20+%20%22andE%22%20+%20rheaders%20+%20%22mentS%22%20+%20div1%5D%28%22%2" ascii
    $s15 = "eventDoc[undelegate + \"p\" + extra + \"n\"]();" fullword ascii
    $s16 = "isArray[\"s\" + tween + \"d\"]();" fullword ascii
    $s17 = "window(\"sibling%20%3D%20%5B%22Msx%22%20+%20clientLeft%20+%20%22Server%22%20+%20elementMatchers%20+%20%22HTTP.6%22%20+%20r20%2C%" ascii
    $s18 = "window(\"eventDoc%20%3D%20beforeunload%5B%22WScrip%22%20+%20resolveContexts%5D%5B%22Creat%22%20+%20rcombinators%20+%20%22ject%22" ascii
    $s19 = "window(\"eventDoc%20%3D%20beforeunload%5B%22WScrip%22%20+%20resolveContexts%5D%5B%22Creat%22%20+%20rcombinators%20+%20%22ject%22" ascii
    $s20 = "window(\"sibling%20%3D%20%5B%22Msx%22%20+%20clientLeft%20+%20%22Server%22%20+%20elementMatchers%20+%20%22HTTP.6%22%20+%20r20%2C%" ascii

  condition:
    uint16(0) == 0x6461 and
    8 of them
}