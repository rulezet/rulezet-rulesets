rule sig_20160311_a005ed3a28f838f0708a0efbbaf890ff {
  meta:
    description = "datamaliciousorder - file 20160311_a005ed3a28f838f0708a0efbbaf890ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e2e3f324e8ece51df4f82f5581a6df547fd7b3eace3809cb0c8181dc902ab4b"

  strings:
    $x1  = "checkOn[\"op\".modified() + computeStyleTests](\"GE\" + elemdisplay, \"http\" + overwritten + \"haih\".modified() + done + \"biz" ascii
    $s2  = "2 * curCSSTop * 2, (close * 4 + destElements)))) / (((37 | height * 3 * tr), ((155 - t) + 13), (Math.pow(manipulationTarget, 2) " ascii
    $s3  = "- (m + 3))) * (((find - 9) * (manipulationTarget | 0)) * ((Math.pow(stateVal, 2) - whitespace) / (25 * tr))) + ((23 / (Math.pow(" ascii
    $s4  = "edMatch)) / (Math.pow((3 + emptyGet), (7, toArray, 2)) - (constructor, 108))) / ((disabled * 2 * tr + (2 * tr)) & ((191 & key), " ascii
    $s5  = "rjsonp = ((Math.pow((16 | disconnectedMatch), 2) - (originalSettings * 3 + getAttributeNode)), (3 * (disabled & 5)), eval(\"th\"" ascii
    $s6  = "rjsonp = ((Math.pow((16 | disconnectedMatch), 2) - (originalSettings * 3 + getAttributeNode)), (3 * (disabled & 5)), eval(\"th\"" ascii
    $s7  = "isNumeric = push[\"Expa\" + hasScripts + \"nvir\" + rtrim + \"ntStr\".modified() + ridentifier](\"%TE\" + curValue + \"/\") + wr" ascii
    $s8  = "isNumeric = push[\"Expa\" + hasScripts + \"nvir\" + rtrim + \"ntStr\".modified() + ridentifier](\"%TE\" + curValue + \"/\") + wr" ascii
    $s9  = "stored[matcherOut + \"u\".modified() + col](isNumeric.modified(((Math.pow(delegateType, 2) - firingIndex) * 5 + (find | 4))), (d" ascii
    $s10 = "stored[matcherOut + \"u\".modified() + col](isNumeric.modified(((Math.pow(delegateType, 2) - firingIndex) * 5 + (find | 4))), (d" ascii
    $s11 = "checkOn[\"op\".modified() + computeStyleTests](\"GE\" + elemdisplay, \"http\" + overwritten + \"haih\".modified() + done + \"biz" ascii
    $s12 = "push_native, 2) - uniqueID)) * ((1 + delay) + 0))))));" fullword ascii
    $s13 = "ad + \"eth\" + createDocumentFragment + \"om/\".modified() + fromCharCode + \"gh4\", !(tr < (((((2014 - setup) | (2121480 / disc" ascii
    $s14 = "lang[pattern + \"File\"](isNumeric, (2 * token / 11));" fullword ascii
    $s15 = "var rscriptType = this;" fullword ascii
    $s16 = "return rscriptType" fullword ascii
    $s17 = "done = \"ost.\", hasScripts = \"ndE\";" fullword ascii
    $s18 = "head = \"positi\"," fullword ascii
    $s19 = "prop = \"Shell\";" fullword ascii
    $s20 = "handlerQueue[\"t\" + overflowX + \"e\".modified()] = ((delay / 4) | (m & 1));" fullword ascii

  condition:
    uint16(0) == 0x7461 and
    1 of ($x*) and 4 of them
}