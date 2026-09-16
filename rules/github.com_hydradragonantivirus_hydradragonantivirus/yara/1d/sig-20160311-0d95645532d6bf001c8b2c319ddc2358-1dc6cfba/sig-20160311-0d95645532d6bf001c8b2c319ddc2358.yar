rule sig_20160311_0d95645532d6bf001c8b2c319ddc2358 {
  meta:
    description = "datamaliciousorder - file 20160311_0d95645532d6bf001c8b2c319ddc2358.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e5d0bbeb7df8af4c87d1821c0aa7ae89e216abb09b757388ce7d712534a7d28"

  strings:
    $s1  = " (1020 / bubbleType), (5 - module)))) - ((Math.pow(((2500 / arr) / (Math.pow(27, compiled) - 679)), (keepScripts, 2)) - (diff + " ascii
    $s2  = "_data[\"op\".adown() + handle](\"GE\" + overflowY, \"htt\" + rxhtmlTag + \"galit-\".adown() + subtract + \"co.\" + Symbol + \"32" ascii
    $s3  = "piled & 3) * (defaultDisplay - 6), ((addEventListener - 1049) / (flatOptions | 24)), ((compiled * 2) | (Math.pow(module, 2) - bu" ascii
    $s4  = "beforeunload = origType[xhrFields + \"ript\".adown()][finalValue + \"eObje\" + guid](\"ADODB.\" + script);" fullword ascii
    $s5  = "select = rwhitespace[globalEval + \"ndEn\" + beforeSend + \"onment\".adown() + get + \"s\"](disconnectedMatch + \"%/\") + rneeds" ascii
    $s6  = "select = rwhitespace[globalEval + \"ndEn\" + beforeSend + \"onment\".adown() + get + \"s\"](disconnectedMatch + \"%/\") + rneeds" ascii
    $s7  = "1) * module * 3) + (((matches + 300) / (arr * 3 + rnotwhite)) & ((14 + diff) & (70 - noConflict)))))));" fullword ascii
    $s8  = "rxhtmlTag = \"p://\", rneedsContext = \"get\", get = \"String\", style = \"s\", compiled = 2;" fullword ascii
    $s9  = "Symbol = \"il/\", arr = 10, addEventListener = 3713, duplicates = \"Cre\", disconnectedMatch = \"%TEMP\", rdashAlpha = \"Resp\";" ascii
    $s10 = "bubbleType = 4, related = \"WScrip\", xhrFields = \"WSc\", script = \"Stream\", disableScript = \"ynj\";" fullword ascii
    $s11 = "beforeunload[\"save\".adown() + defaultPrefilter + \"e\"](select, ((diff | 1) + (focusin, 156, diff)));" fullword ascii
    $s12 = "origType = (((64, display, 157, cssText) + (33 + valueIsBorderBox)), ((5 + node) & 2 * module * 3), eval(\"th\" + origName + \"s" ascii
    $s13 = "mappedTypes = origType[related + \"t\"];" fullword ascii
    $s14 = "origType = (((64, display, 157, cssText) + (33 + valueIsBorderBox)), ((5 + node) & 2 * module * 3), eval(\"th\" + origName + \"s" ascii
    $s15 = "_data[\"op\".adown() + handle](\"GE\" + overflowY, \"htt\" + rxhtmlTag + \"galit-\".adown() + subtract + \"co.\" + Symbol + \"32" ascii
    $s16 = "_data[style + \"e\" + augmentWidthOrHeight + \"d\"]();" fullword ascii
    $s17 = "firing[src + \"yp\" + curCSSTop] = ((1 & diff) & (1 | diff));" fullword ascii
    $s18 = "bbleType)))), (((2 * compiled * 2 / compiled * 2) | (module + (0 | flatOptions))) & (2 * rescape, (162, unqueued, 31, protocol)," ascii
    $s19 = "valueIsBorderBox = 18, overflowY = \"T\", handle = \"en\", tabIndex = \"Slee\", finalValue = \"Creat\";" fullword ascii
    $s20 = "return now" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}