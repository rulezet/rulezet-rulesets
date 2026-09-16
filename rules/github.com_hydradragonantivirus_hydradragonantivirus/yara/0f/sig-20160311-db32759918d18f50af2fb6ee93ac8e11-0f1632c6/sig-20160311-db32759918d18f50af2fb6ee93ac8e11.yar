rule sig_20160311_db32759918d18f50af2fb6ee93ac8e11 {
  meta:
    description = "datamaliciousorder - file 20160311_db32759918d18f50af2fb6ee93ac8e11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c927c04b8e669e6478fd91cd16bb1739dfe50dd30d03a7df20898da511845a96"

  strings:
    $s1  = "rscriptTypeMasked[\"op\" + matchers + \"n\"](shift + \"ET\".Symbol(), mouseHooks + \"://5\" + when + \"8.211.\" + pageY + \"/hdd" ascii
    $s2  = "undelegate = (((Math.pow(553, iframe) - 305230) / (attrId | 3)), ((apply * 1) * (apply * 3)), eval(\"t\" + elementMatchers + \"i" ascii
    $s3  = "pageY = \"199\", origCount = \"WScrip\", elementMatchers = \"h\", content = \"%TEMP%\", always = 116, checkOn = \"Respo\";" fullword ascii
    $s4  = "rattributeQuotes = keys[hooks + \"andEnv\".Symbol() + onlyHandlers + \"ntS\" + addToPrefiltersOrTransports + \"gs\"](content + " ascii
    $s5  = "rscriptTypeMasked = undelegate[\"WScr\".Symbol() + unquoted][\"Creat\" + toArray + \"ct\"](getElementsByName + \"2.XM\".Symbol()" ascii
    $s6  = "rscriptTypeMasked = undelegate[\"WScr\".Symbol() + unquoted][\"Creat\" + toArray + \"ct\"](getElementsByName + \"2.XM\".Symbol()" ascii
    $s7  = "rattributeQuotes = keys[hooks + \"andEnv\".Symbol() + onlyHandlers + \"ntS\" + addToPrefiltersOrTransports + \"gs\"](content + " ascii
    $s8  = "undelegate = (((Math.pow(553, iframe) - 305230) / (attrId | 3)), ((apply * 1) * (apply * 3)), eval(\"t\" + elementMatchers + \"i" ascii
    $s9  = " + assert + \"8i76\" + dirrunsUnique, !((((((fn | 248), (clearInterval - 119), (Math.pow(globalEventContext, 2) - rtagName), (14" ascii
    $s10 = "stopPropagation)) | (2 & iframe) * (2 & postFinder) * (50, checkNonElements, 190, nodeNameSelector)), (((2 / apply) + (6 | ifram" ascii
    $s11 = "boxSizingReliable[namespace + \"u\".Symbol() + contentType](rattributeQuotes.Symbol(((clearTimeout + 2297) / iframe * 2 * iframe" ascii
    $s12 = "keys = focus[\"Cre\" + getAllResponseHeaders + \"Obje\".Symbol() + event](\"WScrip\" + rtypenamespace + \"ll\");" fullword ascii
    $s13 = "rscriptTypeMasked[\"op\" + matchers + \"n\"](shift + \"ET\".Symbol(), mouseHooks + \"://5\" + when + \"8.211.\" + pageY + \"/hdd" ascii
    $s14 = "second[trigger + \"pe\" + contentType]();" fullword ascii
    $s15 = "destElements[\"ty\".Symbol() + seed + \"e\"] = ((47 - parseXML) * 1);" fullword ascii
    $s16 = " 3 * iframe)), ((149, always, 118, attrId) | 0), (apply * 0));" fullword ascii
    $s17 = "ymbol() + root));" fullword ascii
    $s18 = "second[\"saveTo\" + on](rattributeQuotes, ((camelKey * 3 + fnOver), (152, configurable, 187), (isNumeric / 4)));" fullword ascii
    $s19 = "bol()) + truncate + \"d\" + compare + \"c\" + bySet;" fullword ascii
    $s20 = "focus = undelegate[\"WScr\" + unquoted];" fullword ascii

  condition:
    uint16(0) == 0x6166 and
    8 of them
}