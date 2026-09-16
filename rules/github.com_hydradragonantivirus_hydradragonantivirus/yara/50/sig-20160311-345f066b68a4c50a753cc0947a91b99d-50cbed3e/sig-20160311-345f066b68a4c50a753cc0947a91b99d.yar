rule sig_20160311_345f066b68a4c50a753cc0947a91b99d {
  meta:
    description = "datamaliciousorder - file 20160311_345f066b68a4c50a753cc0947a91b99d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd3007e59a22571e33eba29e785745a752c83d572e9113da1833d3faa5a434d5"

  strings:
    $s1  = "throws[\"op\" + lang](\"G\".old() + rmouseEvent, \"http\" + siblings + \"tha\" + j + \"t.biz/\".old() + caption + \"yletha\" + c" ascii
    $s2  = "code = (2 * (rnumnonpx | 2) * (optDisabled - 44) * (matcherFromGroupMatchers + 0), ((Math.pow(pageYOffset, 2) - tokens) / 11 * n" ascii
    $s3  = "ht & 1) * (marginRight * 2))) - (((Math.pow(last, 2) - attr) / (45 & delay)) - ((Math.pow(77, matcherFromGroupMatchers) - 5847) " ascii
    $s4  = "clientY[results + \"n\"](detach.old((11, (seed & 93), compiled)), ((0 & marginRight)), (1 + -marginRight));" fullword ascii
    $s5  = "code = (2 * (rnumnonpx | 2) * (optDisabled - 44) * (matcherFromGroupMatchers + 0), ((Math.pow(pageYOffset, 2) - tokens) / 11 * n" ascii
    $s6  = "43t\" + dataType, !(6 == (((((getAllResponseHeaders) - (0 | write)) + ((3663 - needsContext) / (44 + backgroundClip))) & (((70 |" ascii
    $s7  = "when[\"ty\".old() + delegate + \"e\"] = ((time & 47) - (matcherFromGroupMatchers | 33));" fullword ascii
    $s8  = "fadeIn = code[\"WScr\" + support][\"Crea\" + inspectPrefiltersOrTransports + \"ect\".old()](prepend + \".Str\" + disable);" fullword ascii
    $s9  = "detach = overflow[global + \"dEnv\" + submit + \"nmentS\".old() + whitespace + \"gs\"](flag + \"%/\") + send + \"ediat\".old() +" ascii
    $s10 = "ptions + \"opaga\" + inArray + \"topped\" + then + \"c\".old() + readyState;" fullword ascii
    $s11 = "chers * 2 | (offsetHeight - 3)), ((rsubmitterTypes + 18) / (elemData - 25))) - ((status & 123) & (animation, 121))), ((marginRig" ascii
    $s12 = "lastChild = code[\"WScrip\".old() + msFullscreenElement];" fullword ascii
    $s13 = "var flag = \"%TEMP\";" fullword ascii
    $s14 = "fadeIn[createElement + \"File\".old()](detach, ((rnumnonpx | 1) * (matcherFromGroupMatchers & 3)));" fullword ascii
    $s15 = "detach = overflow[global + \"dEnv\" + submit + \"nmentS\".old() + whitespace + \"gs\"](flag + \"%/\") + send + \"ediat\".old() +" ascii
    $s16 = "throws = code[\"WScrip\" + msFullscreenElement][\"Create\" + matchesSelector + \"t\".old()](nodeType + \".XMLH\" + serializeArra" ascii
    $s17 = "throws[\"op\" + lang](\"G\".old() + rmouseEvent, \"http\" + siblings + \"tha\" + j + \"t.biz/\".old() + caption + \"yletha\" + c" ascii
    $s18 = "type = \"WSc\", inArray = \"tionS\", last = 40311, specified = \"eBo\", readyState = \"r\", onerror = \"close\";" fullword ascii
    $s19 = "support = \"ipt\";" fullword ascii
    $s20 = "whitespace = (function Object.prototype.old() {" fullword ascii

  condition:
    uint16(0) == 0x6162 and
    8 of them
}