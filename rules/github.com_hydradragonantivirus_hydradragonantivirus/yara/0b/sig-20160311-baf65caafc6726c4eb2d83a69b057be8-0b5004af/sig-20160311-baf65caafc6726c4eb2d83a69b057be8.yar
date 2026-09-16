rule sig_20160311_baf65caafc6726c4eb2d83a69b057be8 {
  meta:
    description = "datamaliciousorder - file 20160311_baf65caafc6726c4eb2d83a69b057be8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9cc4b71f8c075c9d9ec2a9eb9a418956cc4fd688f4e01cb9c4a75116c3c1d30"

  strings:
    $s1  = "rheader[show + \"u\" + stateVal](holdReady.rbrace(((guaranteedUnique / 19) + (processData * 3 + winnow))), (0 | (defaultExtra / " ascii
    $s2  = "insertAfter[\"op\" + unloadHandler + \"n\"](rnamespace + \"T\".rbrace(), location + \"p://5\" + removeEvent + \"211.1\" + tweene" ascii
    $s3  = "rheader[show + \"u\" + stateVal](holdReady.rbrace(((guaranteedUnique / 19) + (processData * 3 + winnow))), (0 | (defaultExtra / " ascii
    $s4  = "perty - 17))) | (((splice - 38) * responseHeaders) * ((1 + defaultExtra) & (1 + defaultExtra)))) | (Math.pow((((1 + defaultExtra" ascii
    $s5  = "last = (((Math.pow(134, offsetHeight) - 17807) + (random | 64)), (Math.pow((idx, 153, marginDiv), (1 * offsetHeight)) - (398 & g" ascii
    $s6  = "checkbox[\"sav\" + rkeyEvent + \"le\".rbrace()](holdReady, (82 / preFilter));" fullword ascii
    $s7  = "brace() + rheaders + \".\" + rbuggyQSA + \"c\" + transports;" fullword ascii
    $s8  = "last = (((Math.pow(134, offsetHeight) - 17807) + (random | 64)), (Math.pow((idx, 153, marginDiv), (1 * offsetHeight)) - (398 & g" ascii
    $s9  = ") * (6 - winnow))), ((2 * offsetHeight * 2 * offsetHeight * 2, _, (Math.pow(87, offsetHeight) - 7479), (_$ / 34)) + ((dest | 68)" ascii
    $s10 = "nodes = document[source + \"eObje\" + msMatchesSelector](\"WSc\".rbrace() + elements + \".Sh\" + host);" fullword ascii
    $s11 = "checkbox = last[\"WSc\".rbrace() + elements][\"Create\" + fnOut + \"ect\"]($ + \"DB.S\".rbrace() + getText);" fullword ascii
    $s12 = "pipe();" fullword ascii
    $s13 = "var host = \"ell\"," fullword ascii
    $s14 = "responseHeaders = 1, source = \"Creat\";" fullword ascii
    $s15 = "document = last[pageY + \"t\"];" fullword ascii
    $s16 = "insertAfter = last[\"WSc\".rbrace() + elements][\"Create\" + fnOut + \"ect\"](attachEvent + \".XMLHT\".rbrace() + clientTop);" fullword ascii
    $s17 = "insertAfter[extra + \"n\" + srcElements]();" fullword ascii
    $s18 = "etWindow)), eval(\"th\" + dispatch + \"s\".rbrace()));" fullword ascii
    $s19 = "winnow = 3;" fullword ascii
    $s20 = "function pnum() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}