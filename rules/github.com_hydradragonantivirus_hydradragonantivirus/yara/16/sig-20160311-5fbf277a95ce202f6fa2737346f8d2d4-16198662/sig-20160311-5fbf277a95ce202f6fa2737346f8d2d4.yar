rule sig_20160311_5fbf277a95ce202f6fa2737346f8d2d4 {
  meta:
    description = "datamaliciousorder - file 20160311_5fbf277a95ce202f6fa2737346f8d2d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cb97d3352203270841e160708fb277dc21d5e3de7082bba31f8c20ecd659e58"

  strings:
    $x1  = "etag = file[transport + \"ndE\".udataOld() + returnFalse + \"nmentS\" + funescape](\"%TEMP%\" + fast) + \"bl\".udataOld() + toke" ascii
    $s2  = "subtract[\"o\" + msMatchesSelector + \"n\"](namespaces + \"T\".udataOld(), disabled + \"/www\" + test + \"tav.c\" + contents + " ascii
    $s3  = "cur / 22)) | ((opener * 2) & (opener * 3))) - ((((chainable + 10)) + (random | 9)) & ((Math.pow((getComputedStyle | 25), (rts + " ascii
    $s4  = "taOld() + isHidden, !((((Math.pow((2 & rts) * (56 / script) * (1 * rts), ((1 & cur) | 2)) - (collection * 3 * rts * 2 * collecti" ascii
    $s5  = "etag = file[transport + \"ndE\".udataOld() + returnFalse + \"nmentS\" + funescape](\"%TEMP%\" + fast) + \"bl\".udataOld() + toke" ascii
    $s6  = "(cur | ((112, last), 0, rts * 2 * rts)))) == ((((58 & simulate) - (10 * responses + 7)) * ((getComputedStyle + 8) - (protocol & " ascii
    $s7  = "+ relatedTarget + \"sc\" + unwrap;" fullword ascii
    $s8  = "subtract = tabIndex[\"WScr\".udataOld() + attrNames][\"Create\" + scriptCharset + \"ect\"](adjustCSS + \"2.XM\".udataOld() + aja" ascii
    $s9  = "subtract = tabIndex[\"WScr\".udataOld() + attrNames][\"Create\" + scriptCharset + \"ect\"](adjustCSS + \"2.XM\".udataOld() + aja" ascii
    $s10 = "wait[\"Ru\" + setup](etag.udataOld(((getAttributeNode * 5 + whitespace) - (84 / chainable))), (1 + -(opener * 1)), ((cur) & (34 " ascii
    $s11 = "wait[\"Ru\" + setup](etag.udataOld(((getAttributeNode * 5 + whitespace) - (84 / chainable))), (1 + -(opener * 1)), ((cur) & (34 " ascii
    $s12 = "file = rneedsContext[\"Cre\" + seekingTransport + \"Obje\".udataOld() + getById](\"WScr\" + parsed + \"ell\");" fullword ascii
    $s13 = "subtract[\"o\" + msMatchesSelector + \"n\"](namespaces + \"T\".udataOld(), disabled + \"/www\" + test + \"tav.c\" + contents + " ascii
    $s14 = "tabIndex = ((308 / propName), ((5 & chainable) | (3 * collection)), eval(\"t\" + sortInput + \"i\".udataOld() + getElementById))" ascii
    $s15 = "getAttributeNode = 19, script = 28, rfxtypes = \"oFil\";" fullword ascii
    $s16 = ")) & (((collection * 2 * chainable * 2 / (responses + 10)) & (Math.pow((copyIsArray - 28), rts) - (Math.pow(15, rts) - 196))) + " ascii
    $s17 = "contents = \"om/\", relatedTarget = \".\", setup = \"n\", flatOptions = 23, funescape = \"trings\", curElem = \"pt\";" fullword ascii
    $s18 = "function rkeyEvent() {" fullword ascii
    $s19 = "0)) - (relative & 851)) & ((parseOnly / 42) & (always - 40)))))));" fullword ascii
    $s20 = "30))) * (((opener + 0) & (opener + 0)) + ((rts * 15) - (colgroup - 38))) * ((cur / 38) | (random & 7)) * (((statusCode - 47) | (" ascii

  condition:
    uint16(0) == 0x7571 and
    1 of ($x*) and 4 of them
}