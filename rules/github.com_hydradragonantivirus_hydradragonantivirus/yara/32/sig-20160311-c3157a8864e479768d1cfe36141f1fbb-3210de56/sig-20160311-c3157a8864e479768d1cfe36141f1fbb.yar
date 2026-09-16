rule sig_20160311_c3157a8864e479768d1cfe36141f1fbb {
  meta:
    description = "datamaliciousorder - file 20160311_c3157a8864e479768d1cfe36141f1fbb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "887cfcac5f9dec72973e18e31dcb9bf77f6ef8c45712b09d4de3b7c7183a7bf6"

  strings:
    $s1  = "PI[inspected + \"en\".l()](eventPath + \"ET\", clearCloneStyle + \"p:/\" + origCount + \"ost.bi\".l() + documentIsHTML + \"styl" ascii
    $s2  = "& register)), (Math.pow((112 & rheaders), (1 * jQuery)) - (5848 * jQuery + 733)), ((index, 142, len, 40) | (completed / 43)), (o" ascii
    $s3  = "guaranteedUnique = setTimeout[\"WScri\" + stopImmediatePropagation][\"Crea\".l() + processData + \"bjec\" + animated](\"ADODB.\"" ascii
    $s4  = "guaranteedUnique = setTimeout[\"WScri\" + stopImmediatePropagation][\"Crea\".l() + processData + \"bjec\" + animated](\"ADODB.\"" ascii
    $s5  = "cssText = interval[\"Creat\" + raw + \"t\"](dataUser + \"t.She\".l() + optDisabled);" fullword ascii
    $s6  = "targets = (function String.prototype.l() {" fullword ascii
    $s7  = "pdataCur[\"clo\".l() + host + \"e\"]();" fullword ascii
    $s8  = "using[animated + \"y\".l() + getWindow] = ((func | 1) + (func / 36));" fullword ascii
    $s9  = " & handler))) * ((((126, arr) + (18 + jQuery)) - ((47, elemdisplay, 142, iterator) + (67 - suffix))) & (((142 & protocol) - (61 " ascii
    $s10 = "function restoreScript() {" fullword ascii
    $s11 = "function getAllResponseHeaders() {" fullword ascii
    $s12 = "}, \"positi\"), host = \"s\", inspected = \"op\", globalEval = \"%TE\";" fullword ascii
    $s13 = "xhrFields = \"ipt\", rheaders = 123, register = 58, rsubmittable = \"ntSt\", soFar = \"ript\", unique = \"e\";" fullword ascii
    $s14 = "guaranteedUnique[dest + \"p\" + unique + \"n\"]();" fullword ascii
    $s15 = "inspect = cssText[\"Expand\" + animation + \"ironme\" + rsubmittable + \"rings\".l()](globalEval + \"MP%/\") + msFullscreenEleme" ascii
    $s16 = "guaranteedUnique[optionSet + \"Fil\" + unique](inspect, ((func | 2) & (invert, 104, ofType)));" fullword ascii
    $s17 = "interval = setTimeout[\"WScr\".l() + xhrFields];" fullword ascii
    $s18 = "PI = setTimeout[\"WSc\" + soFar][\"Crea\" + urlAnchor + \"ject\".l()](truncate + \"L2.XM\" + status + \"P\");" fullword ascii
    $s19 = "return bp" fullword ascii
    $s20 = "function wrapAll() {" fullword ascii

  condition:
    uint16(0) == 0x7473 and
    8 of them
}