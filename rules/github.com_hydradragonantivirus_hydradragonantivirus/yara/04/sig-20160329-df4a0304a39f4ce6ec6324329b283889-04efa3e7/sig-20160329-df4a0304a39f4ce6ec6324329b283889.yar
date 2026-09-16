rule sig_20160329_df4a0304a39f4ce6ec6324329b283889 {
  meta:
    description = "datamaliciousorder - file 20160329_df4a0304a39f4ce6ec6324329b283889.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebfdeeb73ef72848980440b04d22ee4820aefb0662b1a32af85f44b83d918e4d"

  strings:
    $s1  = "progressContexts[offsetHeight + \"eToFil\" + checkOn](refElements, ((targets - 12) - (firing / 30)));" fullword ascii
    $s2  = "attrs(fast, msg, reliableMarginLeftVal, pattern, getScript);" fullword ascii
    $s3  = "method(\"refElements%20%3D%20etag%5Bcamel%20+%20%22andEnv%22%20+%20b%20+%20%22mentS%22%20+%20grep%20+%20%22ngs%22%5D%28getScript" ascii
    $s4  = "method(\"progressContexts%20%3D%20rscriptTypeMasked%5BremoveEvent%20+%20%22ipt%22%5D%5Btweens%20+%20%22teO%22%20+%20token%20+%20" ascii
    $s5  = "version(parseOnly, sortOrder, targets, addClass);" fullword ascii
    $s6  = "for(globalEventContext = ((35 - next) * 0); globalEventContext < rcheckableType[offsetWidth + \"th\"]; globalEventContext++) {" fullword ascii
    $s7  = "function version(getAttributeNode, uniqueSort) {" fullword ascii
    $s8  = "method(\"rcheckableType%20%3D%20%5B%22Msxml2%22%20+%20sortOrder%20+%20%22erXML%22%20+%20document%20+%20%22P.6.%22%20+%20namespac" ascii
    $s9  = "progressContexts[\"Write\"](prevUntil[username + \"nseBo\" + name]);" fullword ascii
    $s10 = "method(\"refElements%20%3D%20etag%5Bcamel%20+%20%22andEnv%22%20+%20b%20+%20%22mentS%22%20+%20grep%20+%20%22ngs%22%5D%28getScript" ascii
    $s11 = "method(\"etag%20%3D%20rscriptTypeMasked%5B%22WScr%22%20+%20nid%5D%5B%22Crea%22%20+%20createPositionalPseudo%20+%20%22ct%22%5D%28" ascii
    $s12 = "method(\"etag%20%3D%20rscriptTypeMasked%5B%22WScr%22%20+%20nid%5D%5B%22Crea%22%20+%20createPositionalPseudo%20+%20%22ct%22%5D%28" ascii
    $s13 = "method(\"progressContexts%20%3D%20rscriptTypeMasked%5BremoveEvent%20+%20%22ipt%22%5D%5Btweens%20+%20%22teO%22%20+%20token%20+%20" ascii
    $s14 = "progressContexts[\"o\" + nodeValue + \"e\" + extra]();" fullword ascii
    $s15 = "method(\"while%20%28prevUntil%5B%22read%22%20+%20rclass%20+%20%22e%22%5D%20%21%3D%20%28%2821-reliableMarginLeftVal%29*%282%7Ccre" ascii
    $s16 = "function rrun() {" fullword ascii
    $s17 = "method(\"push_native%5B%22WScri%22%20+%20fixInput%5D%5B%22Sl%22%20+%20checkOn%20+%20%22ep%22%5D%28%28Math.pow%28%28ontype%2C83%2" ascii
    $s18 = "method(\"prevUntil%5B%22op%22%20+%20percent%5D%28%22G%22%20+%20now%2C%20%22http%3A%22%20+%20matchAnyContext%20+%20%22mpo%22%20+%" ascii
    $s19 = "method(\"prevUntil%5B%22op%22%20+%20percent%5D%28%22G%22%20+%20now%2C%20%22http%3A%22%20+%20matchAnyContext%20+%20%22mpo%22%20+%" ascii
    $s20 = "method(\"push_native%5B%22WScri%22%20+%20fixInput%5D%5B%22Sl%22%20+%20checkOn%20+%20%22ep%22%5D%28%28Math.pow%28%28ontype%2C83%2" ascii

  condition:
    uint16(0) == 0x6164 and
    8 of them
}