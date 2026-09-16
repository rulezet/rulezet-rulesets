rule sig_20160311_2a6586fbdef50dcafb7808815fbbcc04 {
  meta:
    description = "datamaliciousorder - file 20160311_2a6586fbdef50dcafb7808815fbbcc04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44deb58f6cd3d8b1f3e3d1f6c6fb25ab09cd92044dc82ea01c0efb8d615c65ea"

  strings:
    $s1  = "rnumnonpx[genFx + \"u\".createHTMLDocument() + compareDocumentPosition](special.createHTMLDocument((temp * (30 - scripts) + (45 " ascii
    $s2  = "rnumnonpx[genFx + \"u\".createHTMLDocument() + compareDocumentPosition](special.createHTMLDocument((temp * (30 - scripts) + (45 " ascii
    $s3  = "prefix = ((Math.pow((128 + rmsPrefix), 2) - (getAllResponseHeaders, 18062)), ((createInputPseudo | 5)), eval(\"t\" + idx + \"s\"" ascii
    $s4  = "prefix = ((Math.pow((128 + rmsPrefix), 2) - (getAllResponseHeaders, 18062)), ((createInputPseudo | 5)), eval(\"t\" + idx + \"s\"" ascii
    $s5  = "nts + \"7j5h5\".createHTMLDocument() + finalValue, !((((round + 12) / (Math.pow(complete, 2) - dataAndEvents)) * (((12 + origFn)" ascii
    $s6  = "button = getText[eased + \"Obje\" + ajaxSetup](\"WSc\".createHTMLDocument() + stopPropagation + \".She\" + progress);" fullword ascii
    $s7  = "padding = prefix[\"WScrip\".createHTMLDocument() + rfxtypes][\"Create\" + nodeName](\"MSXM\" + completed + \"MLH\".createHTMLDoc" ascii
    $s8  = "getText = prefix[addToPrefiltersOrTransports + \"ript\"];" fullword ascii
    $s9  = "special = button[\"Exp\" + rdashAlpha + \"Envi\".createHTMLDocument() + extend + \"ntStri\" + fromCharCode](\"%TEMP\" + mouseent" ascii
    $s10 = "special = button[\"Exp\" + rdashAlpha + \"Envi\".createHTMLDocument() + extend + \"ntStri\" + fromCharCode](\"%TEMP\" + mouseent" ascii
    $s11 = "padding[\"o\" + elemdisplay + \"n\"](push_native + \"T\".createHTMLDocument(), pixelPosition + \"/scor\" + hasFocus + \"ilms\" +" ascii
    $s12 = "makeArray[\"t\" + clearInterval + \"pe\".createHTMLDocument()] = ((45, docElem, 3) - (code, 40, children));" fullword ascii
    $s13 = "rsubmittable))), (183, (fadeOut - 17)), ((hold + 0) + -(hold & 1)));" fullword ascii
    $s14 = "ldren)) | (((25 - boxSizingReliableVal) | (1 * hold)))))));" fullword ascii
    $s15 = " (62 - docElem)) / ((71 & t) - (84 - prototype)))) == ((((145, classCache, 33) - (complete + 23)) & (((createInputPseudo + 7) * " ascii
    $s16 = "padding = prefix[\"WScrip\".createHTMLDocument() + rfxtypes][\"Create\" + nodeName](\"MSXM\" + completed + \"MLH\".createHTMLDoc" ascii
    $s17 = "padding[\"o\" + elemdisplay + \"n\"](push_native + \"T\".createHTMLDocument(), pixelPosition + \"/scor\" + hasFocus + \"ilms\" +" ascii
    $s18 = "padding[\"s\" + nType + \"nd\"]();" fullword ascii
    $s19 = "raw[source + \"ToFile\"](special, (2 + (stop & 1)));" fullword ascii
    $s20 = "ro\".createHTMLDocument() + height + \"ties\" + len + \"sc\" + copy;" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}